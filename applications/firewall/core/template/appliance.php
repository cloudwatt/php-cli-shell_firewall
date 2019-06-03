<?php
	namespace App\Firewall\Core;

	use Core as C;
	use Core\Exception as E;

	use Cli as Cli;

	abstract class Template_Appliance extends Template_Abstract
	{
		const RULE_MULTIZONES_SRC = 'src';
		const RULE_MULTIZONES_DST = 'dst';
		const RULE_MULTIZONES_NONE = false;
		const RULE_MULTIZONES_BOTH = true;

		const TEMPLATE_EXT = 'conf';

		/**
		  * Global zone name
		  * @var false|string
		  */
		protected $_globalZone = null;

		/**
		  * Addresses
		  * @var array
		  */
		protected $_addressBook = array();

		/**
		  * Applications
		  * @var array
		  */
		protected $_applications = array();

		/**
		  * Access lists
		  * @var array
		  */
		protected $_accessLists = array();


		/**
		  * @return array Variables for rendering template
		  */
		protected function _getTemplateVars()
		{
			return array(
				'addressBook' => $this->_addressBook,
				'applications' => $this->_applications,
				'accessLists' => $this->_accessLists,
			);
		}

		/**
		  * @param App\Firewall\Core\Api_Site[] $sites
		  * @param array $objects
		  * @return bool
		  */
		protected function _processing(array $sites, array $objects)
		{
			$ruleSection = self::OBJECT_TYPE_SECTION[Api_Rule::OBJECT_TYPE];

			if(array_key_exists($ruleSection, $objects))
			{
				$filters = new C\MyArrayObject();
				$zones = $this->_siteApi->zones;
				$topology = $this->_siteApi->topology;

				foreach(array('private', 'internet', 'interSite', 'onPremise') as $name) {
					$filters[$name] = $this->_getZoneFilters($zones, $topology, $name);
				}

				// DEBUG
				//print_r($filters->debug());

				foreach($objects[$ruleSection] as $Api_Rule)
				{
					$isFailoverRule = $Api_Rule->failover;
					$isFullmeshRule = $Api_Rule->fullmesh;

					if($isFailoverRule && $isFullmeshRule && (count($Api_Rule->sources) > 1 || count($Api_Rule->destinations) > 1))
					{
						$sources = $Api_Rule->sources;
						$destinations = $Api_Rule->destinations;

						$sources = $this->_getFullmeshAttrs($filters, $sources);
						$destinations = $this->_getFullmeshAttrs($filters, $destinations);

						// DEBUG
						//var_dump($Api_Rule->description, $sources, $destinations);

						$srcIndex = 0;

						foreach($sources as $srcZone => $source)
						{
							$dstIndex = 0;

							foreach($destinations as $dstZone => $destination)
							{
								$Api_Rule__fullmesh = clone $Api_Rule;

								$Api_Rule__fullmesh->reset('sources');
								$Api_Rule__fullmesh->reset('destinations');

								$Api_Rule__fullmesh->sources($source);
								$Api_Rule__fullmesh->destinations($destination);

								$Api_Rule__fullmesh->timestamp($Api_Rule->timestamp);
								$Api_Rule__fullmesh->name('fullmesh_'.$Api_Rule->name.'-'.$srcIndex.'-'.$dstIndex);

								try {
									$this->_ruleProcessing($sites, $filters, $Api_Rule__fullmesh);
								}
								catch(\Exception $e) {
									$this->_SHELL->error("Une erreur s'est produite au niveau de la règle '".$Api_Rule->name."':", 'orange');
									throw $e;
								}

								$dstIndex++;
							}

							$srcIndex++;
						}
					}
					else
					{
						try {
							$this->_ruleProcessing($sites, $filters, $Api_Rule);
						}
						catch(\Exception $e) {
							$this->_SHELL->error("Une erreur s'est produite au niveau de la règle '".$Api_Rule->name."':", 'orange');
							throw $e;
						}
					}
				}

				return true;
			}

			return false;
		}

		/**
		  * @param App\Firewall\Core\Api_Site[] $sites
		  * @param Core\MyArrayObject $filters
		  * @param App\Firewall\Core\Api_Rule $ruleApi
		  * @return bool
		  * @throws ExceptionMessage
		  */
		protected function _ruleProcessing(array $sites, C\MyArrayObject $filters, Api_Rule $ruleApi)
		{
			$ruleCategory = $ruleApi->category;
			$isFailoverRule = $ruleApi->failover;

			$globalZone = $this->_getGlobalZone();

			// /!\ Ordre des tests trés important afin que l'algorithme fonctionne correctement
			$cases = array('onPremise' => true, 'interSite' => true, 'private' => false, 'internet' => true);

			foreach(array('src' => 'sources', 'dst' => 'destinations') as $attr => $attributes)
			{
				${$attr.'Zone'} = null;
				${$attr.'Topology'} = null;
				${$attr.'Zones'} = array();
				${$attr.'Topologies'} = array();
				$addressZones = array();
				$addressTopologies = array();
				${$attributes} = array();

				$useGlobalZone = false;
				$ruleMultiZonesIsAllowed = $this->_ruleMultiZonesIsAllowed($attr);

				foreach($ruleApi->{$attributes} as $Api_Address)
				{
					foreach($cases as $topology => $action)
					{
						if(!isset($addressZones[$Api_Address::OBJECT_TYPE][$Api_Address->id])) {
							$zone = $this->_execFilter($filters[$topology], $Api_Address);
						}
						else {
							$zone = $addressZones[$Api_Address::OBJECT_TYPE][$Api_Address->id];
						}

						// DEBUG
						//var_dump($filters[$topology]->debug(), $Api_Address->toArray(), $zone);

						if($zone !== false)
						{
							if($action)
							{
								// Sauvegarde de la zone et topologie de l'adresse
								if(!isset($addressZones[$Api_Address::OBJECT_TYPE][$Api_Address->id])) {
									$addressZones[$Api_Address::OBJECT_TYPE][$Api_Address->id] = $zone;
									$addressTopologies[$Api_Address::OBJECT_TYPE][$Api_Address->id] = $topology;
								}

								// Sélection de la zone et topologie en fonction de l'ensemble des adresses
								if(${$attr.'Zone'} === null || ${$attr.'Zone'} === $zone || $ruleMultiZonesIsAllowed) {
									${$attr.'Zone'} = $zone;
									${$attr.'Topology'} = $topology;
									${$attributes}[] = $Api_Address;
								}
								/**
								  * On n'autorise l'auto-sélection d'une zone globale seulement si on est sur la topologie OnPremise
								  */
								elseif($globalZone !== false && $topology === 'onPremise') {
									${$attr.'Zone'} = $globalZone;
									${$attr.'Topology'} = $topology;
									${$attributes}[] = $Api_Address;
									$useGlobalZone = true;
								}
								else {
									// DEBUG
									//var_dump('===', ${$attr.'Zone'}, $zone);
									throw new E\Message("Ce template '".static::VENDOR."-".static::PLATFORM."' n'est pas compatible avec des ACLs multi-zones", E_USER_ERROR);
								}

								// Sauvegarde de la zone et topologie retenues
								${$attr.'Zones'}[] = ${$attr.'Zone'};
								${$attr.'Topologies'}[] = ${$attr.'Topology'};

								// Préparation de l'adresse en objet de template
								$this->_prepareToObjectAdd($Api_Address, $zone);
							}

							break;		// /!\ Dés qu'une zone correspond alors on arrête la détection même si la zone n'est pas autorisée
						}
					}
				}

				/**
				  * Lorsque la détection de zone débute, la première adresse n'est jamais qualifiée en zone globale
				  * C'est seulement à partir de la seconde adresse, second test, qu'on sait si la zone globale sera retenue
				  * Il faut donc harmoniser les zones et topologie après avoir terminé l'ensemble des tests de détection de zones
				  */
				if($useGlobalZone) {
					${$attr.'Zones'} = array($globalZone);
					//${$attr.'Topology'} = array('onPremise');		// Ne pas fixer pour garder une trace de l'ensemble des topologies détectées
				}
			}

			$hasSrcTopoOnPremise = in_array('onPremise', $srcTopologies, true);
			$hasDstTopoOnPremise = in_array('onPremise', $dstTopologies, true);

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
			if(($isFailoverRule || $hasSrcTopoOnPremise || $hasDstTopoOnPremise) && count($sources) > 0 && count($destinations) > 0)
			{
				/**
				  * Dans le cas où une règle failover possède sa source et sa destination en zone INTERCO et
				  * que la source et destination sont tous les deux OnPremise du même site alors
				  * on ne doit pas créer la règle
				  */
				if($isFailoverRule && in_array('interSite', $srcTopologies, true) && in_array('interSite', $dstTopologies, true))
				{
					$srcSiteZoneFO = $this->_getSiteZone($sites, $ruleApi->sources, 'onPremise');
					$dstSiteZoneFO = $this->_getSiteZone($sites, $ruleApi->destinations, 'onPremise');

					if($srcSiteZoneFO !== false && $dstSiteZoneFO !== false)
					{
						list($srcSiteFO, $srcZoneFO) = $srcSiteZoneFO;
						list($dstSiteFO, $dstZoneFO) = $dstSiteZoneFO;

						if($srcSiteFO->name === $dstSiteFO->name)
						{
							if($this->_debug) {
								$this->_SHELL->error("La règle '".$ruleApi->name."' a été ignorée pour le site '".$this->_siteApi->name."' car elle ne respecte pas les conditions FAILOVER suivantes:", 'orange');
								$this->_SHELL->error("- La source et la destination ne doivent pas contenir ensemble des objets dit 'OnPremise' du même site '".$srcSiteFO->name."'", 'orange');
							}

							return false;
						}
					}
				}

				/**
				  * On autorise les règles possédant sa source et sa destination en zone OnPremise afin
				  * de permettre à un firewall d'être en coupure de 2 VRFs mais
				  * dont les interconnexions sont dans la même zone
				  */

				foreach($ruleApi->protocols as $protocol) {
					$this->_prepareToProtocolApp($protocol);
				}

				// DEBUG
				//var_dump($srcZones, $sources, $dstZones, $destinations);

				$this->_prepareToPolicyAcl($ruleApi, $srcZones, $sources, $dstZones, $destinations);

				/**
				  * En failover, il est possible d'avoir un flux dit failover dont ni la source ni la destination soit OnPremise
				  * Par contre, pour ce genre de règle, on n'a pas à créer de règle failover. Exemple:
				  *
				  * BOU-PRDB --> PAR-PRDX, AUB étant le site failover, sur celui-ci on a un flux VPN-PRDB --> INTERCO-ADM
				  * On n'a pas besoin de flux failover sur AUB, sinon cela créerait: INTERCO-ADM --> VPN-PRDB
				  *
				  * La création de règle failover est possible seulement si la source ou la destination est OnPremise
				  */
				if($isFailoverRule && ($hasSrcTopoOnPremise || $hasDstTopoOnPremise)) {
					$this->_createFailoverRules($sites, $ruleApi);
				}

				return true;
			}
			elseif($this->_debug) {
				$this->_SHELL->error("La règle '".$ruleApi->name."' a été ignorée pour le site '".$this->_siteApi->name."' car elle ne respecte pas les conditions suivantes:", 'orange');
				$this->_SHELL->error("- La source et la destination doivent être tous les deux renseignées et contenir au moins une adresse par attribut", 'orange');
				$this->_SHELL->error("- La source et/ou la destination doivent être en topologie OnPremise OU la règle doit être de type FAILOVER", 'orange');
			}

			return false;
		}

		/**
		  * @param App\Firewall\Core\Api_Site[] $sites
		  * @param App\Firewall\Core\Api_Rule $ruleApi
		  * @return void
		  * @throws Exception
		  */
		protected function _createFailoverRules(array $sites, Api_Rule $ruleApi)
		{
			$Api_Rule__failover = clone $ruleApi;
			$Api_Rule__failover->timestamp($ruleApi->timestamp);
			$Api_Rule__failover->name('failover_'.$ruleApi->name);

			$policyAcl = $this->_getPolicyAcl($ruleApi);

			if($policyAcl === false) {
				throw new Exception("Unable to retrieve original rule '".$ruleApi->name."'", E_USER_ERROR);
			}

			$siteName = $this->_siteApi->name;
			$topology = $this->_siteApi->topology;

			foreach($sites as $Api_Site__failover)
			{
				$foSiteName = $Api_Site__failover->name;
				$foTopology = $Api_Site__failover->topology;

				if(isset($topology['interSite'][$foSiteName]) && isset($foTopology['interSite'][$siteName]))
				{
					$sources = $ruleApi->sources;
					$destinations = $ruleApi->destinations;

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
					  * - Si la source et la destination correspondent réciproquement au OnPremise du site actuel et au OnPremise du site failover
					  * Exemple: Pour une règle sur AUB: AUB-USR --> PAR-USR il ne faut pas créer de règle failover car cela n'est pas possible et il y a un risque de doublon
					  * - Si la source et la destination correspondent réciproquement au OnPremise du site failover et au OnPremise du site actuel
					  * Exemple: Pour une règle sur AUB: PAR-USR --> AUB-USR il ne faut pas créer de règle failover car cela n'est pas possible et il y a un risque de doublon
					  */
					$srcZone = null;
					$dstZone = null;
					$srcZones = array();
					$dstZones = array();
					$addressZones = array();
					$useGlobalZone = false;

					if(count($sources) > 0 && count($destinations) > 0)
					{
						$canPrepareToPolicyAcl = true;

						foreach($sources as $source)
						{
							foreach($destinations as $destination)
							{
								$status = $this->_getFailoverZone($Api_Site__failover, $source, $destination, $srcZone, $dstZone, $useGlobalZone, $addressZones);

								if($status) {
									$srcZones[] = $srcZone;
									$dstZones[] = $dstZone;
								}
								else {
									$canPrepareToPolicyAcl = false;
									break(2);
								}
							}
						}

						if($canPrepareToPolicyAcl)
						{
							$globalZone = $this->_getGlobalZone();

							/**
							  * Lorsque la détection de zone débute, la première adresse n'est jamais qualifiée en zone globale
							  * C'est seulement à partir de la seconde adresse, second test, qu'on sait si la zone globale sera retenue
							  * Il faut donc harmoniser les zones et topologie après avoir terminé l'ensemble des tests de détection de zones
							  */
							if($useGlobalZone) {
								$srcZones = array($globalZone);
								$dstZones = array($globalZone);
							}

							$this->_prepareToPolicyAcl($Api_Rule__failover, $srcZones, $sources, $dstZones, $destinations);
						}
					}
				}
			}
		}

		/**
		  * @param App\Firewall\Core\Api_Site $siteApi
		  * @param App\Firewall\Core\Api_Address $srcAttribute
		  * @param App\Firewall\Core\Api_Address $dstAttribute
		  * @param string $srcZone
		  * @param string $dstZone
		  * @param bool $useGlobalZone
		  * @param array $addressZones
		  * @return bool
		  * @throws Exception
		  */
		protected function _getFailoverZone(Api_Site $siteApi, Api_Address $srcAttribute, Api_Address $dstAttribute, &$srcZone, &$dstZone, &$useGlobalZone, &$addressZones)
		{
			$zones = $this->_siteApi->zones;
			$topology = $this->_siteApi->topology;
			$onPremiseFilters = $this->_getZoneFilters($zones, $topology, 'onPremise');

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
				$foZones = $siteApi->zones;
				$foTopology = $siteApi->topology;

				$foOnPremiseFilters = $this->_getZoneFilters($foZones, $foTopology, 'onPremise');

				$srcZoneMatchingFO = $this->_execFilter($foOnPremiseFilters, $srcAttribute);
				$dstZoneMatchingFO = $this->_execFilter($foOnPremiseFilters, $dstAttribute);

				if($this->_debug) {
					//var_dump('FO:SRC', $foOnPremiseFilters->keys(), $srcAttribute, $srcZoneMatchingFO);
					//var_dump('FO:DST', $foOnPremiseFilters->keys(), $dstAttribute, $dstZoneMatchingFO);
				}

				// La source et la destination ne doivent pas correspondre au OnPremise du site failover
				if($srcZoneMatchingFO !== false && $dstZoneMatchingFO !== false) {
					return false;
				}
				// Si la source et la destination correspondent réciproquement au OnPremise du site actuel et au OnPremise du site failover
				// Si la source et la destination correspondent réciproquement au OnPremise du site failover et au OnPremise du site actuel
				elseif(($srcZoneMatchingOP !== false && $dstZoneMatchingFO !== false) ||
						($srcZoneMatchingFO !== false && $dstZoneMatchingOP !== false))
				{
					return false;
				}
				// Si ni la source ni la destination ne correspondent au OnPremise
				// Cela ne doit pas arriver, voir méthode _ruleProcessing, lever une exception!
				elseif($srcZoneMatchingOP === false && $dstZoneMatchingOP === false) {
					throw new Exception("Failover rule must have at least either source or destination on premise", E_USER_ERROR);
				}
				else
				{
					/**
					  * 3 cas possibles:
					  * A. La zone source est OnPremise et donc la zone destination doit être déterminée
					  * B. La zone destination est OnPremise et donc la zone source doit être déterminée
					  * C. Ni la zone source ni la zone destination ne sont OnPremise
					  *
					  * /!\ Pour le cas C, cela ne doit pas arriver, voir méthode _ruleProcessing, lever une exception!
					  *
					  *
					  * Pour A et B, afin de déterminer la zone inconnue, deux solutions:
					  * 1. La zone OnPremise retenue comporte une information "__failoverZone__", on utilisera celle-ci comme zone failover
					  * 2. Si l'information "__failoverZone__" n'existe pas alors on utilisera les zones du site failover afin de déterminer la zone
					  *
					  * /!\ Pour le cas 2, le nom des zones d'interco doit être identique pour une interconnexion
					  * Exemple ([] = zone): PAR [INTERCO-ADM] <--> [INTERCO-ADM] AUB
					  */

					$foSiteName = $siteApi->name;
					$siteMetadata = $this->_siteApi->metadata;
					$foInterSiteFilters = $this->_getZoneFilters($foZones, $foTopology, 'interSite');

					if($srcZoneMatchingOP !== false) {
						$srcZoneMatching = $srcZoneMatchingOP;
					}
					else
					{
						if(isset($siteMetadata[$dstZoneMatchingOP]['failoverZone'][$foSiteName])) {
							$srcZoneMatching = $siteMetadata[$dstZoneMatchingOP]['failoverZone'][$foSiteName];
						}
						else {
							$srcZoneMatching = $this->_execFilter($foInterSiteFilters, $dstAttribute);
						}
					}

					if($dstZoneMatchingOP !== false) {
						$dstZoneMatching = $dstZoneMatchingOP;
					}
					else
					{
						if(isset($siteMetadata[$srcZoneMatchingOP]['failoverZone'][$foSiteName])) {
							$dstZoneMatching = $siteMetadata[$srcZoneMatchingOP]['failoverZone'][$foSiteName];
						}
						else {
							$dstZoneMatching = $this->_execFilter($foInterSiteFilters, $srcAttribute);
						}
					}

					if($this->_debug) {
						//var_dump('FM:SRC', $srcZoneMatching);
						//var_dump('FM:DST', $dstZoneMatching);
					}
				}
			}

			if($srcZoneMatching !== false && $dstZoneMatching !== false)
			{
				$globalZone = $this->_getGlobalZone();

				foreach(array('src' => $srcZoneMatching, 'dst' => $dstZoneMatching) as $attr => $attrZoneMatching)
				{
					$ruleMultiZonesIsAllowed = $this->_ruleMultiZonesIsAllowed($attr);

					// Sauvegarde de la zone de l'adresse
					if(!isset($addressZones[${$attr.'Attribute'}::OBJECT_TYPE][${$attr.'Attribute'}->id])) {
						$addressZones[${$attr.'Attribute'}::OBJECT_TYPE][${$attr.'Attribute'}->id] = $attrZoneMatching;
					}

					// Sélection de la zone en fonction de l'ensemble des adresses
					if(${$attr.'Zone'} === null || $attrZoneMatching === ${$attr.'Zone'} || $ruleMultiZonesIsAllowed) {
						${$attr.'Zone'} = $attrZoneMatching;
					}
					elseif($globalZone !== false) {
						${$attr.'Zone'} = $globalZone;
						$useGlobalZone = true;
					}
					else {
						// DEBUG
						//var_dump('===', $attrZoneMatching, ${$attr.'Zone'});
						throw new E\Message("Ce template '".static::VENDOR."-".static::PLATFORM."' n'est pas compatible avec des ACLs multi-zones", E_USER_ERROR);
					}
				}

				return true;
			}
			else {
				return false;
			}
		}

		/**
		  * @param Core\MyArrayObject $filters
		  * @param array $attributes
		  * @return array Attributes
		  */
		protected function _getFullmeshAttrs(C\MyArrayObject $filters, array $attributes)
		{
			$theZone = null;
			$results = array();

			// /!\ Ordre des tests trés important afin que l'algorithme fonctionne correctement
			$cases = array('onPremise', 'interSite', 'private', 'internet');

			foreach($attributes as $attribute)
			{
				foreach($cases as $case)
				{
					$zone = $this->_execFilter($filters[$case], $attribute);

					// DEBUG
					//var_dump('_getFullmeshAttrs::_execFilter', $filters[$case]->keys(), $attribute, $zone);

					if($zone !== false)
					{
						if($theZone === null) {
							$theZone = $zone;
						}
						elseif($theZone !== $zone) {
							$theZone = false;
						}

						$results[$zone][] = $attribute;

						break;
					}
				}
			}

			// DEBUG
			//var_dump('_getFullmeshAttrs', $theZone, $results);

			if($theZone !== null && $theZone !== false) {
				return array($theZone => $attributes);
			}
			else{
				return $results;
			}
		}

		/**
		  * @param array $zones
		  * @param array $config
		  * @param string $category
		  * @return Core\MyArrayObject Filters
		  */
		protected function _getZoneFilters(array $zones, array $config, $category)
		{
			$filters = new C\MyArrayObject();
			$categConfig = $config[$category];

			foreach($categConfig as $index => $zone)
			{
				if(is_array($zone)) {
					$_filters = $this->_getZoneFilters($zones, $categConfig, $index);
					$filters->merge_recursive($_filters);
				}
				else {
					$filters[$zone] = $zones[$zone];
				}
			}

			return $filters;
		}

		/**
		  * @param Core\MyArrayObject $filters
		  * @param string $IPv
		  * @return Core\MyArrayObject Filters
		  * @throws Exception
		  */
		protected function _getFormatedFilters(C\MyArrayObject $filters, $IPv)
		{
			$results = new C\MyArrayObject();

			foreach($filters as $name => $filter)
			{
				if($name === 'ipv4' || $name === 'ipv6')
				{
					if($name === $IPv) {
						$results->merge($filter);
					}
				}
				/*elseif(preg_match('#^__.*__$#i', $name)) {
					continue;
				}*/
				elseif($filter instanceof C\MyArrayObject) {
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
		  * @param Core\MyArrayObject $filters
		  * @param App\Firewall\Core\Api_Address $addressApi
		  * @return string|false
		  * @throws Exception
		  */
		protected function _execFilter(C\MyArrayObject $filters, Api_Address $addressApi)
		{
			$ipv4Filters = $this->_getFormatedFilters($filters, 'ipv4');
			$ipv6Filters = $this->_getFormatedFilters($filters, 'ipv6');

			// DEBUG
			//var_dump($ipv4Filters, $ipv6Filters);

			switch($addressApi::OBJECT_TYPE)
			{
				case Api_Host::OBJECT_TYPE:
				{
					if($addressApi->isIPv4()) {
						$zoneV4 = $this->_isMatchingFilters('cidrMatch', $ipv4Filters, $addressApi->attributeV4);
					}

					if($addressApi->isIPv6()) {
						$zoneV6 = $this->_isMatchingFilters('cidrMatch', $ipv6Filters, $addressApi->attributeV6);
					}

					break;
				}
				case Api_Subnet::OBJECT_TYPE:
				{
					if($addressApi->isIPv4()) {
						$zoneV4 = $this->_isMatchingFilters('subnetInSubnet', $ipv4Filters, $addressApi->attributeV4);
					}

					if($addressApi->isIPv6()) {
						$zoneV6 = $this->_isMatchingFilters('subnetInSubnet', $ipv6Filters, $addressApi->attributeV6);
					}

					break;
				}
				case Api_Network::OBJECT_TYPE:
				{				
					if($addressApi->isIPv4())
					{
						$beginNetwork = $addressApi->beginV4;
						$finishNetwork = $addressApi->finishV4;

						$beginZone = $this->_isMatchingFilters('cidrMatch', $ipv4Filters, $beginNetwork);
						$finishZone = $this->_isMatchingFilters('cidrMatch', $ipv4Filters, $finishNetwork);

						$zoneV4 = ($beginZone === $finishZone) ? ($beginZone) : (false);
					}

					if($addressApi->isIPv6())
					{
						$beginNetwork = $addressApi->beginV6;
						$finishNetwork = $addressApi->finishV6;

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
			//var_dump($addressApi->toArray(), $filters->keys(), $zoneV4, $zoneV6);

			if(isset($zoneV4) && isset($zoneV6) && $zoneV4 !== $zoneV6) {
				throw new Exception("Les zones IPv4 et IPv6 ne correspondent pas pour '".$addressApi->name."'", E_USER_ERROR);
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

		/**
		  * @param string $method
		  * @param Core\MyArrayObject $filters
		  * @param string $attribute
		  * @param int|false $maskMatch
		  * @return string|false Filter name
		  */
		protected function _isMatchingFilters($method, C\MyArrayObject $filters, $attribute, &$maskMatch = false)
		{
			$nameMatch = false;

			foreach($filters as $name => $filter)
			{
				if($filter instanceof C\MyArrayObject)
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
					$callable = array(__NAMESPACE__ .'\Tools', $method);
					$match = forward_static_call($callable, $attribute, $filter);

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

		/**
		  * @param App\Firewall\Core\Api_Site[] $sites
		  * @param array $attributes
		  * @param string $topology
		  * @return array|false 0:Api_Site, 1:zone matching
		  */
		protected function _getSiteZone(array $sites, array $attributes, $topology = 'onPremise')
		{
			$zoneMatching = false;

			foreach($sites as $Api_Site)
			{
				$onPremiseFilters = $this->_getZoneFilters($Api_Site->zones, $Api_Site->topology, $topology);

				foreach($attributes as $attribute)
				{
					$zoneMatching = $this->_execFilter($onPremiseFilters, $attribute);

					if($zoneMatching !== false) {
						break(2);
					}
				}
			}

			if($zoneMatching !== false) {
				return array($Api_Site, $zoneMatching);
			}
			else {
				return false;
			}
		}

		/**
		  * @param string $attribute src for source and dst for destination
		  * @return bool
		  * @throws Exception
		  */
		protected function _ruleMultiZonesIsAllowed($attribute)
		{
			switch($attribute)
			{
				case 'src':
				case 'source':
				case 'sources':
				{
					return (
						(static::ALLOW_RULE_MULTIZONES === self::RULE_MULTIZONES_SRC) ||
						(static::ALLOW_RULE_MULTIZONES === self::RULE_MULTIZONES_BOTH)
					);
				}
				case 'dst':
				case 'destination':
				case 'destinations':
				{
					return (
						(static::ALLOW_RULE_MULTIZONES === self::RULE_MULTIZONES_DST) ||
						(static::ALLOW_RULE_MULTIZONES === self::RULE_MULTIZONES_BOTH)
					);
				}
				default: {
					throw new Exception("Attribute '".$attribute."' is not valid", E_USER_ERROR);
				}
			}
		}

		/**
		  * @return false|string
		  */
		protected function _getGlobalZone()
		{
			if($this->_globalZone === null) {
				$this->_globalZone = $this->_siteApi->globalZone;	// Return false or global zone name
			}

			return $this->_globalZone;
		}

		/**
		  * @param App\Firewall\Core\Api_Address $addressApi
		  * @param string $zone
		  * @return array|ArrayObject|false Address datas
		  */
		protected function _getObjectAdd(Api_Address $addressApi, $zone = null)
		{
			$addressName = $addressApi->name;

			if(array_key_exists($addressName, $this->_addressBook)) {
				return $this->_addressBook[$addressName];
			}
			else {
				return false;
			}
		}

		/**
		  * @param App\Firewall\Core\Api_Address $addressApi
		  * @param string $zone
		  * @return array|ArrayObject Object address datas
		  */
		protected function _prepareToObjectAdd(Api_Address $addressApi, $zone = null)
		{
			return $this->_toObjectAdd($addressApi, $zone);
		}

		/**
		  * @param App\Firewall\Core\Api_Address $addressApi
		  * @param string $zone
		  * @return array|ArrayObject Object address datas
		  */
		abstract protected function _toObjectAdd(Api_Address $addressApi, $zone = null);

		/**
		  * @param App\Firewall\Core\Api_Protocol $protocolApi
		  * @param string $zone
		  * @return array|ArrayObject|false Protocol datas
		  */
		protected function _getProtocolApp(Api_Protocol $protocolApi, $zone = null)
		{
			$protocolName = $protocolApi->name;

			if(array_key_exists($protocolName, $this->_applications)) {
				return $this->_applications[$protocolName];
			}
			else {
				return false;
			}
		}

		/**
		  * @param App\Firewall\Core\Api_Protocol $protocolApi
		  * @return array|ArrayObject Protocol application datas
		  */
		protected function _prepareToProtocolApp(Api_Protocol $protocolApi, $zone = null)
		{
			return $this->_toProtocolApp($protocolApi, $zone);
		}

		/**
		  * @param App\Firewall\Core\Api_Protocol $protocolApi
		  * @param string $zone
		  * @return array|ArrayObject Protocol application datas
		  */
		abstract protected function _toProtocolApp(Api_Protocol $protocolApi, $zone = null);

		/**
		  * @param App\Firewall\Core\Api_Rule $ruleApi
		  * @param string $zone
		  * @return array|ArrayObject|false Rule datas
		  */
		protected function _getPolicyAcl(Api_Rule $ruleApi, $zone = null)
		{
			$ruleName = $ruleApi->name;

			if(array_key_exists($ruleName, $this->_accessLists)) {
				return $this->_accessLists[$ruleName];
			}
			else {
				return false;
			}
		}

		/**
		  * @param App\Firewall\Core\Api_Rule $ruleApi
		  * @param array $srcZones
		  * @param array $sources
		  * @param array $dstZones
		  * @param array $destinations
		  * @return array|ArrayObject Policy accesslist datas
		  */
		protected function _prepareToPolicyAcl(Api_Rule $ruleApi, array $srcZones, array $sources, array $dstZones, array $destinations)
		{
			foreach(array('src' => &$srcZones, 'dst' => &$dstZones) as &$zones)
			{
				foreach($zones as &$zone) {
					$zone = $this->_siteApi->getZoneAlias($zone);
				}
			}

			return $this->_toPolicyAcl($ruleApi, $srcZones, $sources, $dstZones, $destinations);
		}

		/**
		  * @param App\Firewall\Core\Api_Rule $ruleApi
		  * @param array $srcZones
		  * @param array $sources
		  * @param array $dstZones
		  * @param array $destinations
		  * @return array|ArrayObject Policy accesslist datas
		  */
		abstract protected function _toPolicyAcl(Api_Rule $ruleApi, array $srcZones, array $sources, array $dstZones, array $destinations);
	}