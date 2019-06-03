<?php
	namespace App\Firewall;

	use SplFileObject;

	use Core as C;
	use Core\Exception as E;

	use App\Firewall\Core;

	class Shell_Program_Firewall_Config_Extension_Csv extends Shell_Program_Firewall_Config_Extension_Abstract
	{
		const TAG_SEPARATOR = ';';
		const CSV_DELIMITER = ';';


		/**
		  * @param string $filename File to load
		  * @param string $prefix Rule name prefix
		  * @param string $suffix Rule name suffix
		  * @return false|int Number of rules loaded
		  * @throw Core\Exception\Message
		  */
		public function load($filename, $prefix = null, $suffix = null)
		{
			$configs = $this->_load($filename);

			if(count($configs) > 0) {
				return $this->_import($configs, true, $prefix, $suffix);
			}
			else {
				return false;
			}
		}

		/**
		  * @param string $filename File target
		  * @param array $configs Configurations to save
		  * @return bool
		  * @throw Core\Exception\Message
		  */
		public function save($filename, array $configs)
		{
			$configs = $this->_export($configs);

			if(count($configs) > 0) {
				return $this->_save($configs, $filename);
			}
			else {
				return true;
			}
		}

		/**
		  * @param string $filename File to import
		  * @param string $prefix Rule name prefix
		  * @param string $suffix Rule name suffix
		  * @return false|int Number of rules imported
		  * @throw Core\Exception\Message
		  */
		public function import($filename, $prefix = null, $suffix = null)
		{
			$configs = $this->_load($filename);

			if(count($configs) > 0) {
				return $this->_import($configs, false, $prefix, $suffix);
			}
			else {
				return false;
			}
		}

		/**
		  * @param string $filename File target
		  * @param array $configs Configurations to export
		  * @return bool
		  * @throw Core\Exception\Message
		  */
		public function export($filename, array $configs)
		{
			$configs = $this->_export($configs);

			if(count($configs) > 0) {
				return $this->_save($configs, $filename);
			}
			else {
				return true;
			}
		}

		/**
		  * @param string $filename Configuration filename
		  * @return array
		  */
		protected function _load($filename)
		{
			$configs = array();

			if(file_exists($filename) && is_readable($filename))
			{
				$SplFileObject = new SplFileObject($filename, 'r');
				//$SplFileObject->setFlags(SplFileObject::DROP_NEW_LINE);

				foreach($SplFileObject as $index => $line)
				{
					if(C\Tools::is('string&&!empty', $line)) {
						$configs[] = str_getcsv($line, self::CSV_DELIMITER);
					}
				}
			}

			return $configs;
		}

		/**
		  * @param array $configs Configurations to save
		  * @param string $filename Configuration filename
		  * @return bool
		  */
		protected function _save(array $configs, $filename)
		{
			$status = false;

			$fileExists = file_exists($filename);
			$pathname = pathinfo($filename, PATHINFO_DIRNAME);

			if((!$fileExists && is_writable($pathname)) || ($fileExists && is_writable($filename)))
			{
				$fp = fopen($filename, 'w');

				if($fp !== false)
				{
					foreach($configs as $config)
					{
						$status = fputcsv($fp, $config, self::CSV_DELIMITER);

						if($status === false) {
							break;
						}
					}

					fclose($fp);
				}
			}

			return $status;
		}

		/**
		  * @param array $configs Configuration
		  * @param bool $keepName Keep name or allow to rewrite it
		  * @param string $prefix Rule name prefix
		  * @param string $suffix Rule name suffix
		  * @return int Number of rules imported
		  * @throw Core\Exception\Message
		  */
		protected function _import(array $configs, $keepName, $prefix, $suffix)
		{
			$csvName = null;
			$ruleCounter = 0;

			$type = Core\Api_Rule::OBJECT_TYPE;

			if(!$keepName) {
				$baseRuleName = $this->_ruleFwProgram->getNextName($type);
			}

			// /!\ Du plus précis au plus large
			$addressTypes = array(
				Core\Api_Host::OBJECT_TYPE,
				Core\Api_Subnet::OBJECT_TYPE,
				Core\Api_Network::OBJECT_TYPE
			);

			// /!\ Important pour $csvName et $append
			usort($configs, function($a, $b) {
				return strnatcasecmp($a[0], $b[0]);
			});

			foreach($configs as $index => $config)
			{
				if(count($config) !== 11) {
					throw new E\Message("Impossible d'importer les règles, fichier CSV non valide", E_USER_ERROR);
				}

				/**
				  * Permet de garantir l'unicité des noms des règles
				  * Permet de garantir l'idempotence lors de l'export
				  */
				$configRuleName = $config[0];

				if($csvName === $configRuleName) {
					$append = true;
				}
				else {
					$append = false;
					$csvName = $configRuleName;
					unset($Core_Api_Rule);
				}

				switch($config[1])
				{
					case Core\Api_Rule::CATEG_FAILOVER: {
						$category = Core\Api_Rule::CATEG_FAILOVER;
						break;
					}
					default: {
						$category = Core\Api_Rule::CATEG_MONOSITE;
					}
				}

				$fullmesh = ($config[2] === 'fullmesh');
				$state = ($config[3] === 'active');
				$action = ($config[4] === 'permit');

				$source = $config[5];
				$destination = $config[6];
				$protocol = $config[7];
				$description = $config[8];
				$tags = $config[9];
				$timestamp = (int) $config[10];

				foreach(array('src' => $source, 'dst' => $destination) as $attr => $attribute)
				{
					${'Core_Api_Address__'.$attr} = false;

					/**
					  * On recherche d'abord localement pour l'ensemble des types
					  * puis ensuite si pas de résultat alors on crée l'objet à partir de l'IPAM
					  */
					foreach($addressTypes as $addressType)
					{
						${'Core_Api_Address__'.$attr} = $this->_addressFwProgram->getObject($addressType, $attribute, true);

						if(${'Core_Api_Address__'.$attr} !== false) {
							break;
						}
					}

					if(${'Core_Api_Address__'.$attr} === false)
					{
						foreach($addressTypes as $addressType)
						{
							/**
							  * Peut prendre du temps lors de l'utilisation de l'API IPAM pour les recherches d'adresses
							  * Permet à l'utilisateur de renseigner une adresse dans le CSV sans que celle-ci existe au préalable en local
							  *
							  * /!\ Risque de bug lorsqu'un host et un subnet sont nommés pareil
							  */
							try {
								${'Core_Api_Address__'.$attr} = $this->_addressFwProgram->autoCreateObject($addressType, $attribute, true);
							}
							catch(E\Message $e) {
								$this->_SHELL->throw($e);
							}
							catch(\Exception $e) {
								$this->_SHELL->error($e->getMessage(), 'orange');
							}

							if(is_object(${'Core_Api_Address__'.$attr})) {
								break;
							}
						}
					}
				}

				if($Core_Api_Address__src instanceof Core\Api_Address && $Core_Api_Address__dst instanceof Core\Api_Address)
				{
					$Core_Api_Protocol = new Core\Api_Protocol($protocol, $protocol);
					$isValidProtocol = $Core_Api_Protocol->protocol($protocol);

					if($isValidProtocol && $Core_Api_Protocol->isValid())
					{
						/**
						  * /!\ Si quelque chose se passe mal il faut arrêter l'importation
						  * Le système "append" ne permet pas de poursuivre en cas d'erreur
						  */
						if(!$append)
						{
							if(!C\Tools::is('string&&!empty', $prefix)) $prefix = false;
							if(!C\Tools::is('string&&!empty', $suffix)) $suffix = false;

							if($keepName) {
								$name = $configRuleName;
							}
							else {
								/**
								  * Ne pas utiliser index car certaines règles sont mises à jour
								  * ruleCounter qui correspond exactement au nombre de nouvelles règles
								  */
								$name = $baseRuleName + $ruleCounter;
							}

							$name = $prefix.$name.$suffix;

							try {
								$Core_Api_Rule = $this->_ruleFwProgram->insert($type, $name, null);
							}
							catch(\Exception $e) {
								$this->_SHELL->throw($e);
								$Core_Api_Rule = null;
							}

							if($Core_Api_Rule instanceof Core\Api_Rule)
							{
								$Core_Api_Rule->category($category);
								$Core_Api_Rule->fullmesh($fullmesh);
								$Core_Api_Rule->state($state);
								$Core_Api_Rule->action($action);
								$Core_Api_Rule->description($description);

								$tags = preg_split('#(?<!\\\\)'.preg_quote(self::TAG_SEPARATOR, '#').'#i', $tags);

								foreach($tags as $tag)
								{
									$tag = str_ireplace('\\'.self::TAG_SEPARATOR, self::TAG_SEPARATOR, $tag);

									$Core_Api_Tag = new Core\Api_Tag($tag, $tag);
									$tagStatus = $Core_Api_Tag->tag($tag);

									if($tagStatus && $Core_Api_Tag->isValid()) {
										$Core_Api_Rule->tag($Core_Api_Tag);
									}
								}

								$Core_Api_Rule->timestamp($timestamp);
							}
						}

						if($Core_Api_Rule instanceof Core\Api_Rule)
						{
							/**
							  * /!\ Risque de doublon si Core\Api_Rule n'a pas la sécurité
							  *
							  * Pour simplifier on essaie d'ajouter à chaque fois source et destination
							  * mais dans certains cas il se peut que cela crée des doublons en source et/ou en destination
							  *
							  * Example: une règle avec une source mais deux destinations sera découpée en deux lignes dans le CSV
							  * Lors du chargement du CSV, on va tenter d'ajouter deux fois la source puisqu'elle figure sur les deux lignes
							  *
							  * Idem pour le protocole, risque de doublon lorsque le changement se situe au niveau de la source ou de la destination
							  *
							  * @todo coder une vérification en amont ou laisser Core\Api_Rule faire le job de vérification?
							  */
							$Core_Api_Rule->addSource($Core_Api_Address__src);
							$Core_Api_Rule->addDestination($Core_Api_Address__dst);
							$Core_Api_Rule->addProtocol($Core_Api_Protocol);

							$status = false;

							if($Core_Api_Rule->isValid())
							{
								$status = true;

								/**
								  * Afficher juste les messages et ne pas bloquer
								  * afin de permettre à l'utilisateur de corriger
								  */
								try {
									$Core_Api_Rule->checkOverlapAddress();
								}
								catch(E\Message $e) {
									$this->_SHELL->error("RULE '".$Core_Api_Rule->name."': ".$e->getMessage(), 'orange');
								}

								if(!$append) {
									$ruleCounter++;
									$this->_SHELL->print("Règle '".$Core_Api_Rule->name."' (position ".$configRuleName.") importée!", 'green');
								}
								else {
									$this->_SHELL->print("Règle '".$Core_Api_Rule->name."' (position ".$configRuleName.") mis à jour!", 'green');
								}
							}

							if(!$status)
							{
								try {
									$status = $this->_ruleFwProgram->drop($Core_Api_Rule);
								}
								catch(\Exception $e) {
									$this->_SHELL->throw($e);
									$status = null;
								}

								throw new E\Message("La règle '".$configRuleName."' semble invalide et n'a pas pu être importée", E_USER_ERROR);
							}
						}
						else {
							throw new E\Message("Une erreur s'est produite durant l'importation d'une règle", E_USER_ERROR);
						}
					}
					else {
						throw new E\Message("L'attribut protocole de la règle '".$configRuleName."'est invalide", E_USER_ERROR);
					}
				}
				else {
					throw new E\Message("La règle '".$configRuleName."' possède des attributs incorrects (source ou destination) [".$source."] [".$destination."]", E_USER_ERROR);
				}
			}

			/**
			  * Sécurité afin de s'assurer que l'ordre des règles est correct
			  * /!\ NE PAS EFFECTUER UN KSORT SINON LE GIT DIFF NE SERA PAS LISIBLE
			  */
			//uksort($this->_objects[Core\Api_Rule::OBJECT_KEY], 'strnatcasecmp');

			return $ruleCounter;
		}

		/**
		  * @param array $configs Configurations to export
		  * @return array
		  */
		protected function _export(array $configs)
		{
			$items = array();

			if(array_key_exists(Core\Api_Rule::OBJECT_KEY, $configs))
			{
				$rules = $configs[Core\Api_Rule::OBJECT_KEY];

				foreach($rules as $rule)
				{
					// /!\ CSV fields order !!
					$item = array();
					$item[0] = $rule['name'];
					$item[1] = $rule['category'];
					$item[2] = ($rule['fullmesh']) ? ('fullmesh') : ('');
					$item[3] = ($rule['state']) ? ('active') : ('inactive');
					$item[4] = ($rule['action']) ? ('permit') : ('deny');
					$item[5] = null;
					$item[6] = null;
					$item[7] = null;
					$item[8] = $rule['description'];
					$item[9] = null;
					$item[10] = $rule['timestamp'];

					array_walk($rule['tags'], function(&$tag) {
						$tag = str_ireplace(self::TAG_SEPARATOR, '\\'.self::TAG_SEPARATOR, $tag);
					});

					$item[9] = implode(self::TAG_SEPARATOR, $rule['tags']);

					/**
					  * @todo bug, si source/destination existent en differents types (host, subnet, network) --> faire un check?
					  * /!\ Risque de bug lorsqu'un host et un subnet sont nommés pareil
					  */

					$typeSeparator = preg_quote(Core\Api_Rule::SEPARATOR_TYPE, '#');
					$typeRegex = '#^([^\s:]+'.$typeSeparator.')#i';

					foreach($rule['sources'] as $source)
					{
						$item[5] = preg_replace($typeRegex, '', $source);

						foreach($rule['destinations'] as $destination)
						{
							$item[6] = preg_replace($typeRegex, '', $destination);

							foreach($rule['protocols'] as $protocol) {
								$item[7] = preg_replace($typeRegex, '', $protocol);
								//ksort($item);
								$items[] = $item;
							}
						}
					}

					// /!\ Ne plus modifier $item à partir d'ici
				}
			}

			return $items;
		}
	}