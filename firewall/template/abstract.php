<?php
	abstract class Firewall_Template_Abstract
	{
		const OBJECT_TYPE_SECTION = array(
			Firewall_Api_Host::OBJECT_TYPE => 'hosts',
			Firewall_Api_Subnet::OBJECT_TYPE => 'subnets',
			Firewall_Api_Network::OBJECT_TYPE => 'networks',
			Firewall_Api_Rule::OBJECT_TYPE => 'rules'
		);

		const SECTION_TYPE_VAR = array(
			'hosts' => 'hosts',
			'subnets' => 'subnets',
			'networks' => 'networks',
			'rules' => 'rules'
		);

		protected $_MAIN;
		protected $_CONFIG;

		protected $_sites;

		protected $_applications = array();
		protected $_addressBook = array();
		protected $_accessLists = array();

		protected $_template;
		protected $_export;


		public function __construct(Service_Abstract $MAIN, array $sites)
		{
			$this->_MAIN = $MAIN;
			$this->_CONFIG = CONFIG::getInstance();

			$this->_sites = $sites;
		}

		/**
		  * @param FIREWALL_Abstract $FIREWALL_Abstract
		  * @param array $sections
		  * @return bool
		  */
		public function templating(FIREWALL_Abstract $FIREWALL_Abstract, array $sections)
		{
			$objects = array();

			foreach($sections as $section)
			{
				// @todo array objects a la place?? a voir
				if(array_key_exists($section, self::SECTION_TYPE_VAR)) {
					$varName = self::SECTION_TYPE_VAR[$section];
					$objects[$section] = $FIREWALL_Abstract->{$varName};
				}
			}

			return $this->_rendering($FIREWALL_Abstract->site, $objects);
		}

		/**
		  * @param Firewall_Site $Firewall_Site Current site
		  * @param array $objects Current objects
		  * @return bool
		  */
		protected function _rendering(Firewall_Site $Firewall_Site, array $objects)
		{
			$sites = $this->_sites;

			// /!\ Doit travailler sur une copie
			foreach($sites as $index => $Firewall_Api_Site)
			{
				if($Firewall_Api_Site->name === $Firewall_Site->name) {
					unset($sites[$index]);
				}
			}

			$status = $this->_preProcessing($Firewall_Site, $sites, $objects);

			// DEBUG
			//var_dump($this->_applications, $this->_addressBook, $this->_accessLists);

			if($status)
			{
				$this->_template = $this->_getTemplate();

				ob_start();
				require $this->_template;
				$config = ob_get_clean();

				$this->_export = $this->_getExport($Firewall_Site->hostname);
				$pathname = pathinfo($this->_export, PATHINFO_DIRNAME);

				if((!file_exists($this->_export) && is_writable($pathname)) || (file_exists($this->_export) && is_writable($this->_export)))
				{
					$status = file_put_contents($this->_export, $config, LOCK_EX);

					if($status !== false) {
						return true;
					}
					elseif(file_exists($this->_export)) {
						unlink($this->_export);
					}
				}
			}

			return false;
		}

		/**
		  * @param Firewall_Site $Firewall_Site
		  * @param array $sites
		  * @param array $objects
		  * @return bool
		  */
		protected function _preProcessing(Firewall_Site $Firewall_Site, array $sites, array $objects)
		{
			$ruleSection = self::OBJECT_TYPE_SECTION[Firewall_Api_Rule::OBJECT_TYPE];

			if(array_key_exists($ruleSection, $objects))
			{
				$filters = new MyArrayObject();
				$site = $Firewall_Site->toObject();

				foreach(array('private', 'internet', 'interSite', 'onPremise') as $name) {
					$filters[$name] = $this->_getZoneFilters($site->zones, $site->topology, $name);
				}

				// DEBUG
				//print_r($filters->debug());

				foreach($objects[$ruleSection] as $Firewall_Api_Rule)
				{
					$isFailoverRule = $Firewall_Api_Rule->failover;
					$isFullmeshRule = $Firewall_Api_Rule->fullmesh;

					if($isFailoverRule && $isFullmeshRule && (count($Firewall_Api_Rule->sources) > 1 || count($Firewall_Api_Rule->destinations) > 1))
					{
						$sources = $Firewall_Api_Rule->sources;
						$destinations = $Firewall_Api_Rule->destinations;

						$sources = $this->_getFullmeshAttrs($filters, $sources);
						$destinations = $this->_getFullmeshAttrs($filters, $destinations);

						// DEBUG
						//var_dump($Firewall_Api_Rule->description, $sources, $destinations);

						foreach($sources as $srcIndex => $source)
						{
							foreach($destinations as $dstIndex => $destination)
							{
								$fullmeshRule = clone $Firewall_Api_Rule;

								$fullmeshRule->reset('src');
								$fullmeshRule->reset('dst');

								if(!is_array($source)) {
									$fullmeshRule->source($source);
								}
								else {
									$fullmeshRule->sources($source);
								}

								if(!is_array($destination)) {
									$fullmeshRule->destination($destination);
								}
								else {
									$fullmeshRule->destinations($destination);
								}

								$fullmeshRule->name('fullmesh_'.$Firewall_Api_Rule->name.'-'.$srcIndex.'-'.$dstIndex);
								$this->_ruleProcessing($Firewall_Site, $sites, $filters, $fullmeshRule);
							}
						}
					}
					else {
						$this->_ruleProcessing($Firewall_Site, $sites, $filters, $Firewall_Api_Rule);
					}
				}

				return true;
			}

			return false;
		}

		/**
		  * @param Firewall_Site $Firewall_Site
		  * @param array $sites
		  * @param MyArrayObject $filters
		  * @param Firewall_Api_Rule $Firewall_Api_Rule
		  * @return bool
		  */
		protected function _ruleProcessing(Firewall_Site $Firewall_Site, array $sites, MyArrayObject $filters, Firewall_Api_Rule $Firewall_Api_Rule)
		{
			$ruleCategory = $Firewall_Api_Rule->category;
			$isFailoverRule = $Firewall_Api_Rule->failover;

			foreach(array('src' => 'sources', 'dst' => 'destinations') as $attr => $attributes)
			{
				${$attr.'Zone'} = null;
				${$attr.'Topology'} = null;
				${$attributes} = array();

				foreach($Firewall_Api_Rule->{$attributes} as $Firewall_Api_Address)
				{
					// /!\ Ordre des tests trés important afin que l'algorithme fonctionne correctement
					$cases = array('onPremise' => true, 'interSite' => true, 'private' => false, 'internet' => true);

					foreach($cases as $topology => $action)
					{
						$zone = $this->_execFilter($filters[$topology], $Firewall_Api_Address);

						// DEBUG
						//var_dump($filters[$topology]->debug(), $Firewall_Api_Address->toArray(), $zone);

						if($zone !== false)
						{
							if($action)
							{
								if(${$attr.'Zone'} === null || ${$attr.'Zone'} === $zone)
								{
									${$attr.'Zone'} = $zone;
									${$attr.'Topology'} = $topology;
									${$attributes}[] = $Firewall_Api_Address;

									// DEBUG
									//var_dump($Firewall_Api_Address->toArray(), $zone);

									$this->_toObjectAdd($Firewall_Api_Address, $zone);
								}
								else {
									// DEBUG
									//var_dump('===', ${$attr.'Zone'}, $zone);
									//var_dump($Firewall_Api_Rule->description);
									throw new Exception("Ce template '".self::PLATFORM."-".self::TEMPLATE."' n'est pas compatible avec des ACLs multi-zones", E_USER_ERROR);
								}
							}

							break;		// /!\ Dés qu'une zone corresponde alors on arrête la détection même si la zone n'est pas autorisée
						}
					}
				}
			}

			/**
			  * En monosite, il est obligatoire d'avoir soit la source soit la destination OnPremise
			  * En failover, il est possible d'avoir un flux dit failover dont ni la source ni la destination soit OnPremise
			  *
			  * Si l'utilisateur souhaite créer une règle simple de régularisation INTERCO --> WAN par exemple alors il doit:
			  * - Ajouter qu'un seul site celui où il souhaite effectuer la régularisation
			  * - Créer une règle de catégorie failover et la configurer basiquement
			  *
			  * (($isMonositeRule && ($srcTopology === 'onPremise' || $dstTopology === 'onPremise')) || $isFailoverRule)
			  */
			if(($isFailoverRule || $srcTopology === 'onPremise' || $dstTopology === 'onPremise') &&
					count($sources) > 0 && count($destinations) > 0)
			{
				/**
				  * Dans le cas où une règle failover posséde sa source et sa destination en zone INTERCO et
				  * que la source et destination sont tous les deux OnPremise du même site alors
				  * on ne doit pas créer la règle
				  */
				if($isFailoverRule && $srcTopology === 'interSite' && $dstTopology === 'interSite')
				{
					$srcSiteZoneFO = $this->_getSiteZone($sites, $Firewall_Api_Rule->sources, 'onPremise');
					$dstSiteZoneFO = $this->_getSiteZone($sites, $Firewall_Api_Rule->destinations, 'onPremise');

					if($srcSiteZoneFO !== false && $dstSiteZoneFO !== false)
					{
						list($srcSiteFO, $srcZoneFO) = $srcSiteZoneFO;
						list($dstSiteFO, $dstZoneFO) = $dstSiteZoneFO;

						if($srcSiteFO->name === $dstSiteFO->name) {
							return false;
						}
					}
				}

				/**
				  * On autorise les règles possédant sa source et sa destination en zone OnPremise afin
				  * de permettre à un firewall d'être en coupure de 2 VRFs mais
				  * dont les interconnexions sont dans la même zone
				  */

				foreach($Firewall_Api_Rule->protocols as $protocol) {
					$this->_toProtocolApp($protocol);
				}

				// DEBUG
				//var_dump($srcZone, $sources, $dstZone, $destinations);

				$this->_toPolicyAcl($Firewall_Api_Rule, $srcZone, $sources, $dstZone, $destinations);

				/**
				  * En failover, il est possible d'avoir un flux dit failover dont ni la source ni la destination soit OnPremise
				  * Par contre, pour ce genre de règle, on n'a pas à créer de règle failover. Exemple:
				  *
				  * BOU-PRDB --> PAR-PRDX, AUB étant le site failover, sur celui-ci on a un flux VPN-PRDB --> INTERCO-ADM
				  * On n'a pas besoin de flux failover sur AUB, sinon cela créerait: INTERCO-ADM --> VPN-PRDB
				  *
				  * La création de règle failover est possible seulement si la source ou la destination est OnPremise
				  */
				if($isFailoverRule && ($srcTopology === 'onPremise' || $dstTopology === 'onPremise')) {
					$this->_createFailoverRules($Firewall_Site, $sites, $Firewall_Api_Rule);
				}

				return true;
			}

			return false;
		}

		/**
		  * @param Firewall_Site $Firewall_Site
		  * @param array $sites
		  * @param Firewall_Api_Rule $Firewall_Api_Rule
		  * @return string|false
		  */
		protected function _createFailoverRules(Firewall_Site $Firewall_Site, array $sites, Firewall_Api_Rule $Firewall_Api_Rule)
		{
			$Firewall_Api_Rule__failover = clone $Firewall_Api_Rule;
			$Firewall_Api_Rule__failover->name('failover_'.$Firewall_Api_Rule->name);

			$policyAcl = $this->_getPolicyAcl($Firewall_Api_Rule);

			if($policyAcl === false) {
				throw new Exception("Unable to retreive original rule '".$Firewall_Api_Rule->name."'", E_USER_ERROR);
			}

			$siteName = $Firewall_Site->name;
			$site = $Firewall_Site->toObject();

			foreach($sites as $Firewall_Api_Site__failover)
			{
				$foSiteName = $Firewall_Api_Site__failover->name;

				if(isset($site->topology->interSite->{$foSiteName}))
				{
					$Firewall_Site__failover = $Firewall_Api_Site__failover->config;
					$foSite = $Firewall_Site__failover->toObject();

					if(isset($foSite->topology->interSite->{$siteName}))
					{
						$onPremiseFilters = $this->_getZoneFilters($site->zones, $site->topology, 'onPremise');
						$foOnPremiseFilters = $this->_getZoneFilters($foSite->zones, $foSite->topology, 'onPremise');
						$foInterSiteFilters = $this->_getZoneFilters($foSite->zones, $foSite->topology, 'interSite');

						$sources = $Firewall_Api_Rule->sources;
						$destinations = $Firewall_Api_Rule->destinations;

						/**
						  * /!\ Le système de détection de la zone INTERCO fonctionne seulement si le nom des zones d'interco est identique pour une interconnexion
						  * Exemple ([] = zone): PAR [INTERCO-ADM] <--> [INTERCO-ADM] AUB
						  *
						  * Pour chaque couple source/destination:
						  * - Source correspond aux filtres OnPremise du site actuel alors zone OnPremise est utilisé en source
						  * - Source ne correspond pas aux filtres OnPremise, alors destination doit correspondre aux filtres InterSite du site failover
						  * - Destination correspond aux filtres OnPremise du site actuel alors zone OnPremise est utilisé en destination
						  * - Destination ne correspond pas aux filtres OnPremise, alors source doit correspondre aux filtres InterSite du site failover
						  *
						  * Pour chaque traitement d'un couple, si la zone source/destination ne correspond pas à celle d'un traitement précédent alors émettre une exception
						  * A la fin si une seule zone source et une seule zone destination ont été trouvées alors on peut créer la règle failover en utilisant ces zones
						  *
						  * Il ne doit pas avoir de règle failover dans les cas suivants:
						  * - Si la source et la destination correspondent au OnPremise du site actuelle
						  * Exemple: Pour une règle sur AUB: AUB-USR-INF --> AUB-USR-PIF il ne faut pas bloquer cette règle mais il ne faut pas de règle failover
						  * - Si la source et la destination correspondent au OnPremise du site failover
						  * Exemple: Pour une règle sur AUB: PAR-USR-INF --> PAR-USR-PIF il ne faut pas de règle failover car cela n'est pas possible
						  * - Si la source et la destination correspondent réciproquement au OnPremise du site actuel et au onPremise du site failover
						  * Exemple: Pour une règle sur AUB: AUB-USR --> PAR-USR il ne faut pas créer de règle failover car cela n'est pas possible et il y a un risque de doublon
						  * - Si la source et la destination correspondent réciproquement au OnPremise du site failover et au onPremise du site actuel
						  * Exemple: Pour une règle sur AUB: PAR-USR --> AUB-USR il ne faut pas créer de règle failover car cela n'est pas possible et il y a un risque de doublon
						  */
						$srcZone = null;
						$dstZone = null;

						foreach($sources as $source)
						{
							foreach($destinations as $destination)
							{
								$status = $this->_getFailoverZone($onPremiseFilters, $foOnPremiseFilters, $foInterSiteFilters, $source, $destination, $srcZone, $dstZone);

								if($status === false) {
									$srcZone = $dstZone = null;
									break(2);
								}
							}
						}

						if($srcZone !== null && $dstZone !== null) {
							$this->_toPolicyAcl($Firewall_Api_Rule__failover, $srcZone, $policyAcl['sources'], $dstZone, $policyAcl['destinations']);
						}
					}
				}
			}
		}

		protected function _getFailoverZone(MyArrayObject $onPremiseFilters, MyArrayObject $foOnPremiseFilters, MyArrayObject $foInterSiteFilters,
			Firewall_Api_Address $srcAttribute, Firewall_Api_Address $dstAttribute, &$srcZone, &$dstZone)
		{
			$srcZoneMatchingOP = $this->_execFilter($onPremiseFilters, $srcAttribute);
			$dstZoneMatchingOP = $this->_execFilter($onPremiseFilters, $dstAttribute);

			// DEBUG
			//var_dump('OP:SRC', $onPremiseFilters->keys(), $srcAttribute, $srcZoneMatchingOP);
			//var_dump('OP:DST', $onPremiseFilters->keys(), $dstAttribute, $dstZoneMatchingOP);

			// La source et la destination ne doivent pas correspondre au OnPremise du site actuelle
			if($srcZoneMatchingOP !== false && $dstZoneMatchingOP !== false) {
				return false;
			}
			else
			{
				$srcZoneMatchingFO = $this->_execFilter($foOnPremiseFilters, $srcAttribute);
				$dstZoneMatchingFO = $this->_execFilter($foOnPremiseFilters, $dstAttribute);

				// DEBUG
				//var_dump('FO:SRC', $foOnPremiseFilters->keys(), $srcAttribute, $srcZoneMatchingFO);
				//var_dump('FO:DST', $foOnPremiseFilters->keys(), $dstAttribute, $dstZoneMatchingFO);

				// La source et la destination ne doivent pas correspondre au OnPremise du site failover
				if($srcZoneMatchingFO !== false && $dstZoneMatchingFO !== false) {
					return false;
				}
				// Si la source et la destination correspondent réciproquement au OnPremise du site actuel et au onPremise du site failover
				// Si la source et la destination correspondent réciproquement au OnPremise du site failover et au onPremise du site actuel
				elseif(($srcZoneMatchingOP !== false && $dstZoneMatchingFO !== false) ||
							($srcZoneMatchingFO !== false && $dstZoneMatchingOP !== false))
				{
					return false;
				}
				else
				{
					if($srcZoneMatchingOP === false) {
						$srcZoneMatching = $this->_execFilter($foInterSiteFilters, $dstAttribute);
					}
					else {
						$srcZoneMatching = $srcZoneMatchingOP;
					}

					if($dstZoneMatchingOP === false) {
						$dstZoneMatching = $this->_execFilter($foInterSiteFilters, $srcAttribute);
					}
					else {
						$dstZoneMatching = $dstZoneMatchingOP;
					}

					// DEBUG
					//var_dump('FM:SRC', $srcZoneMatching);
					//var_dump('FM:DST', $dstZoneMatching);
				}
			}

			if($srcZoneMatching !== false && $dstZoneMatching !== false)
			{
				foreach(array('srcZone' => $srcZoneMatching, 'dstZone' => $dstZoneMatching) as $attrZone => $attrZoneMatching)
				{
					// DEBUG
					//var_dump('===', $attrZoneMatching, ${$attrZone});

					if(${$attrZone} === null || $attrZoneMatching === ${$attrZone}) {
						${$attrZone} = $attrZoneMatching;
					}
					else {
						// DEBUG
						//var_dump('===', $attrZoneMatching, ${$attrZone});
						throw new Exception("Ce template '".self::PLATFORM."-".self::TEMPLATE."' n'est pas compatible avec des ACLs multi-zones", E_USER_ERROR);
					}
				}

				return true;
			}
			else {
				return false;
			}
		}

		protected function _getFullmeshAttrs(MyArrayObject $filters, array $attributes)
		{
			$hasOnlyOneZone = null;
			$hasOnPremiseAddress = false;
			$hasNotOnPremiseAddress = false;

			// /!\ Ordre des tests trés important afin que l'algorithme fonctionne correctement
			$cases = array('onPremise', 'interSite', 'private', 'internet');

			foreach($attributes as $attribute)
			{
				$zone = $this->_execFilter($filters['onPremise'], $attribute);

				$hasOnPremiseAddress = ($hasOnPremiseAddress || ($zone !== false));
				$hasNotOnPremiseAddress = ($hasNotOnPremiseAddress || ($zone === false));

				foreach($cases as $case)
				{
					$zone = $this->_execFilter($filters[$case], $attribute);

					// DEBUG
					//var_dump('_getFullmeshAttrs::_execFilter', $filters[$case]->keys(), $attribute, $zone);

					if($zone !== false)
					{
						if($hasOnlyOneZone === null) {
							$hasOnlyOneZone = $zone;
						}
						elseif($hasOnlyOneZone !== false && $hasOnlyOneZone !== $zone) {
							$hasOnlyOneZone = false;
						}

						break;
					}
				}
			}

			// DEBUG
			//var_dump('_getFullmeshAttrs', $hasOnPremiseAddress, $hasNotOnPremiseAddress, $hasOnlyOneZone);

			if(($hasOnPremiseAddress && !$hasNotOnPremiseAddress) ||
				($hasOnlyOneZone !== null && $hasOnlyOneZone !== false))
			{
				return array($attributes);
			}
			else{
				return $attributes;
			}
		}

		protected function _getZoneFilters(MyArrayObject $zones, MyArrayObject $config, $category)
		{
			$filters = new MyArrayObject();
			$categConfig = $config->{$category};

			foreach($categConfig as $index => $zone)
			{
				if($zone instanceof MyArrayObject) {
					$_filters = $this->_getZoneFilters($zones, $categConfig, $index);
					$filters->merge_recursive($_filters);
				}
				else {
					$filters[$zone] = $zones->{$zone};
				}
			}

			return $filters;
		}

		protected function _getFormatedFilters(MyArrayObject $filters, $IPv)
		{
			$results = new MyArrayObject();

			foreach($filters as $name => $filter)
			{
				if($name === 'ipv4' || $name === 'ipv6')
				{
					if($name === $IPv) {
						$results->merge($filter);
					}
				}
				elseif($filter instanceof MyArrayObject) {
					$_filter = $this->_getFormatedFilters($filter, $IPv);
					$results->merge(array($name => $_filter));
				}
				else {
					throw new Exception("Zone filters format is not valid", E_USER_ERROR);
				}
			}

			return $results;
		}

		/**
		  * @param MyArrayObject $filters
		  * @param Firewall_Api_Address $Firewall_Api_Address
		  * @return string|false
		  */
		protected function _execFilter(MyArrayObject $filters, Firewall_Api_Address $Firewall_Api_Address)
		{
			$ipv4Filters = $this->_getFormatedFilters($filters, 'ipv4');
			$ipv6Filters = $this->_getFormatedFilters($filters, 'ipv6');

			// DEBUG
			//var_dump($ipv4Filters, $ipv6Filters);

			switch($Firewall_Api_Address::OBJECT_TYPE)
			{
				case Firewall_Api_Host::OBJECT_TYPE:
				{
					if($Firewall_Api_Address->isIPv4()) {
						$zoneV4 = $this->_isMatchingFilters('cidrMatch', $ipv4Filters, $Firewall_Api_Address->attributeV4);
					}

					if($Firewall_Api_Address->isIPv6()) {
						$zoneV6 = $this->_isMatchingFilters('cidrMatch', $ipv6Filters, $Firewall_Api_Address->attributeV6);
					}

					break;
				}
				case Firewall_Api_Subnet::OBJECT_TYPE:
				{
					if($Firewall_Api_Address->isIPv4()) {
						$zoneV4 = $this->_isMatchingFilters('subnetInSubnet', $ipv4Filters, $Firewall_Api_Address->attributeV4);
					}

					if($Firewall_Api_Address->isIPv6()) {
						$zoneV6 = $this->_isMatchingFilters('subnetInSubnet', $ipv6Filters, $Firewall_Api_Address->attributeV6);
					}

					break;
				}
				case Firewall_Api_Network::OBJECT_TYPE:
				{				
					if($Firewall_Api_Address->isIPv4())
					{
						$beginNetwork = $Firewall_Api_Address->beginV4;
						$finishNetwork = $Firewall_Api_Address->finishV4;

						$beginZone = $this->_isMatchingFilters('cidrMatch', $ipv4Filters, $beginNetwork);
						$finishZone = $this->_isMatchingFilters('cidrMatch', $ipv4Filters, $finishNetwork);

						$zoneV4 = ($beginZone === $finishZone) ? ($beginZone) : (false);
					}

					if($Firewall_Api_Address->isIPv6())
					{
						$beginNetwork = $Firewall_Api_Address->beginV6;
						$finishNetwork = $Firewall_Api_Address->finishV6;

						$beginZone = $this->_isMatchingFilters('cidrMatch', $ipv6Filters, $beginNetwork);
						$finishZone = $this->_isMatchingFilters('cidrMatch', $ipv6Filters, $finishNetwork);

						$zoneV6 = ($beginZone === $finishZone) ? ($beginZone) : (false);
					}

					break;
				}
				default: {
					return false;
				}
			}

			// DEBUG
			//var_dump($Firewall_Api_Address->toArray(), $filters->keys(), $zoneV4, $zoneV6);

			if(isset($zoneV4) && isset($zoneV6) && $zoneV4 !== $zoneV6) {
				throw new Exception("Les zones IPv4 et IPv6 ne correspondent pour '".$Firewall_Api_Address->name."'", E_USER_ERROR);
			}
			elseif(isset($zoneV4)) {
				return $zoneV4;
			}
			elseif(isset($zoneV6)) {
				return $zoneV6;
			}
			else {
				return false;
			}
		}

		protected function _isMatchingFilters($method, MyArrayObject $filters, $attribute, &$maskMatch = false)
		{
			$nameMatch = false;

			foreach($filters as $name => $filter)
			{
				if($filter instanceof MyArrayObject)
				{
					$match = $this->_isMatchingFilters($method, $filter, $attribute, $maskMatch);

					/**
					  * On souhaite retourner le nom du filtre du 1er niveau
					  */
					if($match !== false) {
						$nameMatch = $name;
					}
				}
				else
				{
					$match = forward_static_call(array('NETWORK_Tools', $method), $attribute, $filter);

					if($match !== false)
					{
						/**
						  * Permet de garantir que si plusieurs filtres match
						  * alors on garde celui avec le masque le plus précis
						  */
						$filterParts = explode('/', $filter, 2);
						$mask = (int) $filterParts[1];

						if($maskMatch === false || $mask > $maskMatch) {
							$nameMatch = $name;
							$maskMatch = $mask;
						}
					}
				}
			}

			return $nameMatch;
		}

		protected function _getSiteZone(array $sites, array $attributes, $topology = 'onPremise')
		{
			$zoneMatching = false;

			foreach($sites as $Firewall_Api_Site)
			{
				$Firewall_Site = $Firewall_Api_Site->config;
				$site = $Firewall_Site->toObject();

				$onPremiseFilters = $this->_getZoneFilters($site->zones, $site->topology, $topology);

				foreach($attributes as $attribute)
				{
					$zoneMatching = $this->_execFilter($onPremiseFilters, $attribute);

					if($zoneMatching !== false) {
						break(2);
					}
				}
			}

			if($zoneMatching !== false) {
				return array($Firewall_Api_Site, $zoneMatching);
			}
			else {
				return false;
			}
		}

		protected function _getObjectAdd(Firewall_Api_Address $Firewall_Api_Address, $zone)
		{
			$addressName = $Firewall_Api_Address->name;

			if(isset($this->_addressBook[$zone]) && array_key_exists($addressName, $this->_addressBook[$zone])) {
				return $this->_addressBook[$zone][$addressName];
			}
			else {
				return false;
			}
		}

		protected function _getProtocolApp(Firewall_Api_Protocol $Firewall_Api_Protocol)
		{
			$protocolName = $Firewall_Api_Protocol->name;

			if(array_key_exists($protocolName, $this->_applications)) {
				return $this->_applications[$protocolName];
			}
			else {
				return false;
			}
		}

		protected function _getPolicyAcl(Firewall_Api_Rule $Firewall_Api_Rule)
		{
			$ruleName = $Firewall_Api_Rule->name;

			if(array_key_exists($ruleName, $this->_accessLists)) {
				return $this->_accessLists[$ruleName];
			}
			else {
				return false;
			}
		}

		abstract protected function _toObjectAdd(Firewall_Api_Address $Firewall_Api_Address, $zone);

		abstract protected function _toProtocolApp(Firewall_Api_Protocol $Firewall_Api_Protocol);

		abstract protected function _toPolicyAcl(Firewall_Api_Rule $Firewall_Api_Rule, $srcZone, array $sources, $dstZone, array $destinations);

		protected function _getTemplate()
		{
			$pathname = $this->_CONFIG->FIREWALL->configuration->templates->path;
			return Tools::filename(rtrim($pathname, '/').'/'.static::PLATFORM.'-'.static::TEMPLATE.'.php');
		}

		protected function _getExport($name)
		{
			$pathname = $this->_CONFIG->FIREWALL->configuration->exports->path;
			return Tools::filename(rtrim($pathname, '/').'/'.$name.'.conf');
		}

		public function __get($name)
		{
			switch($name)
			{
				case 'template': {
					return $this->_template;
				}
				case 'export': {
					return $this->_export;
				}
				default: {
					throw new Exception("This attribute '".$name."' does not exist", E_USER_ERROR);
				}
			}
		}
	}