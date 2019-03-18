<?php
	namespace App\Firewall;

	use SplFileObject;

	use Core as C;
	use Core\Exception as E;

	use App\Firewall\Core;

	class Shell_Program_Firewall_Config_Extension_Csv extends Shell_Program_Firewall_Config_Extension_Abstract
	{
		const CSV_DELIMITER = ';';


		public function load($filename)
		{
			return $this->_load($filename, true);
		}

		public function save($filename, array $configs)
		{
			$filename = $this->_jsonFilenameToCsv($filename);
			$configs = $this->_export($configs);

			if(count($configs) > 0)
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
			else {
				return true;
			}
		}

		public function import($filename)
		{
			return $this->_load($filename, false);
		}

		/**
		  * @param string $filename Configuration filename
		  * @param bool $keepName  Keep name or allow to rewrite it
		  * @return bool|int Number of rules imported
		  * @throw App\Firewall\Exception|Core\Exception\Message
		  */
		protected function _load($filename, $keepName = true)
		{
			$configs = array();
			$filename = $this->_jsonFilenameToCsv($filename);

			if(file_exists($filename) && is_readable($filename))
			{
				$SplFileObject = new SplFileObject($filename, 'r');

				foreach($SplFileObject as $index => $line)
				{
					if(C\Tools::is('string&&!empty', $line)) {
						$configs[] = str_getcsv($line, self::CSV_DELIMITER);
					}
				}

				return $this->_import($configs, $keepName);
			}
			else {
				return false;
			}
		}

		/**
		  * @param array $configs Configuration
		  * @param bool $keepName Keep name or allow to rewrite it
		  * @return int Number of rules imported
		  * @throw App\Firewall\Exception|Core\Exception\Message
		  */
		protected function _import(array $configs, $keepName)
		{
			$csvName = null;
			$ruleCounter = 0;

			// /!\ Du plus précis au plus large
			$addressTypes = array(
				Core\Api_Host::OBJECT_TYPE,
				Core\Api_Subnet::OBJECT_TYPE,
				Core\Api_Network::OBJECT_TYPE
			);

			$Shell_Program_Firewall_Object_Rule = new Shell_Program_Firewall_Object_Rule($this->_SHELL, $this->_objects);
			$Shell_Program_Firewall_Object_Address = new Shell_Program_Firewall_Object_Address($this->_SHELL, $this->_objects);

			// /!\ Important pour $csvName et $append
			usort($configs, function($a, $b)
			{
				if($a[0] === $b[0]) {
					return 0;
				}

				return ($a[0] < $b[0]) ? (-1) : (1);
			});

			foreach($configs as $config)
			{
				/**
				  * Permet de garantir l'unicité des noms des règles
				  * Permet de garantir l'idempotence lors de l'export
				  */
				$ruleName = $config[0];

				if($csvName === $ruleName) {
					$append = true;
				}
				else {
					$append = false;
					$csvName = $ruleName;
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
				$timestamp = (int) $config[9];

				foreach(array('src' => $source, 'dst' => $destination) as $attr => $attribute)
				{
					${'Core_Api_Address__'.$attr} = false;

					/**
					  * On recherche d'abord localement pour l'ensemble des types
					  * puis ensuite si pas de résultat alors on crée l'objet à partir de l'IPAM
					  */
					foreach($addressTypes as $addressType)
					{
						${'Core_Api_Address__'.$attr} = $Shell_Program_Firewall_Object_Address->getObject($addressType, $attribute, true);

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
							${'Core_Api_Address__'.$attr} = $Shell_Program_Firewall_Object_Address->autoCreateObject($addressType, $attribute, true);

							if(is_object(${'Core_Api_Address__'.$attr})) {
								break;
							}
						}
					}
				}

				if($Core_Api_Address__src instanceof Core\Api_Address && $Core_Api_Address__dst instanceof Core\Api_Address)
				{
					$Core_Api_Protocol = new Core\Api_Protocol($protocol);
					$isValidProtocol = $Core_Api_Protocol->protocol($protocol);

					if($isValidProtocol)
					{
						/**
						  * /!\ Si quelque chose se passe mal il faut arrêter l'importation
						  * Le système "append" ne permet pas de poursuivre en cas d'erreur
						  */
						if(!$append)
						{
							$type = Core\Api_Rule::OBJECT_TYPE;
							$name = ($keepName) ? ($ruleName) : (null);

							try {
								$Core_Api_Rule = $Shell_Program_Firewall_Object_Rule->insert($type, $name, null);
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
								$Core_Api_Rule->timestamp($timestamp);

								$name = $Core_Api_Rule->name;
							}
						}
						else
						{
							try {
								$Core_Api_Rule = $Shell_Program_Firewall_Object_Rule->update($type, $name);
							}
							catch(\Exception $e) {
								$this->_SHELL->throw($e);
								$Core_Api_Rule = null;
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

							if($Core_Api_Rule->isValid())
							{
								if(!$append) {
									$ruleCounter++;
									$this->_SHELL->print("Règle '".$Core_Api_Rule->name."' (position ".$ruleName.") importée!", 'green');
								}
								else {
									$this->_SHELL->print("Règle '".$Core_Api_Rule->name."' (position ".$ruleName.") mis à jour!", 'green');
								}
							}
							else
							{
								try {
									$status = $Shell_Program_Firewall_Object_Rule->delete($Core_Api_Rule);
								}
								catch(\Exception $e) {
									$this->_SHELL->throw($e);
									$status = null;
								}

								throw new E\Message("La règle '".$ruleName."' semble invalide et n'a pas pu être importée", E_USER_ERROR);
							}
						}
						else {
							throw new E\Message("Une erreur s'est produite durant l'importation d'une règle", E_USER_ERROR);
						}
					}
					else {
						throw new E\Message("L'attribut protocole de la règle '".$ruleName."'est invalide", E_USER_ERROR);
					}
				}
				else {
					throw new E\Message("La règle '".$ruleName."' possède des attributs incorrects (source ou destination) [".$source."] [".$destination."]", E_USER_ERROR);
				}
			}

			/**
			  * Sécurité afin de s'assurer que l'ordre des règles est correct
			  */
			ksort($this->_objects[Core\Api_Rule::OBJECT_KEY]);

			return $ruleCounter;
		}

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
					$item[9] = $rule['timestamp'];

					/**
					  * @todo bug, si source/destination existent en differents types (host, subnet, network) --> faire un check?
					  * /!\ Risque de bug lorsqu'un host et un subnet sont nommés pareil
					  */

					foreach($rule['sources'] as $source)
					{
						$item[5] = preg_replace('#^([^\s:]+::)#i', '', $source);

						foreach($rule['destinations'] as $destination)
						{
							$item[6] = preg_replace('#^([^\s:]+::)#i', '', $destination);

							foreach($rule['protocols'] as $protocol) {
								$item[7] = preg_replace('#^([^\s:]+::)#i', '', $protocol);
								//ksort($item);
								$items[] = $item;
							}
						}
					}
				}
			}

			return $items;
		}

		protected function _jsonFilenameToCsv($filename)
		{
			return preg_replace('#(\.json)$#i', '.csv', $filename);
		}
	}