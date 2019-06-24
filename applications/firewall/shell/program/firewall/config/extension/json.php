<?php
	namespace App\Firewall;

	use SplFileObject;

	use Core as C;
	use Core\Exception as E;

	use App\Firewall\Core;

	class Shell_Program_Firewall_Config_Extension_Json extends Shell_Program_Firewall_Config_Extension_Abstract
	{
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
		  * @param string $filename File to load
		  * @return bool
		  * @throw Core\Exception\Message
		  */
		public function loadAddresses($filename)
		{
			$configs = $this->_load($filename);

			if(count($configs) > 0) {
				$counter = $this->_importAddresses($configs, true);
				return ($counter >= 0);
			}
			else {
				return false;
			}
		}

		/**
		  * @param string $filename File to load
		  * @return bool
		  * @throw Core\Exception\Message
		  */
		public function loadSites($filename)
		{
			$configs = $this->_load($filename);

			if(count($configs) > 0) {
				$counter = $this->_importSites($configs, true);
				return ($counter >= 0);
			}
			else {
				return false;
			}
		}

		/**
		  * @param string $filename Configuration filename
		  * @param string $addressesField
		  * @param string $sitesField
		  * @param string $rulesField
		  * @param bool $checkValidity
		  * @return bool
		  * @throw Core\Exception\Message
		  */
		public function apply($filename, $addressesField, $sitesField, $rulesField, $checkValidity = true)
		{		
			$configs = $this->_load($filename);

			if(count($configs) > 0)
			{
				$counterA = $this->_importAddresses($configs[$addressesField], $checkValidity);
				$counterS = $this->_importSites($configs[$sitesField], $checkValidity);
				$counterR = $this->_importRules($configs[$rulesField], true, null, null, $checkValidity);

				return ($counterA !== false && $counterS !== false && $counterR !== false);
			}
			else {
				return true;
			}
		}

		/**
		  * @param string $filename Configuration filename
		  * @return array
		  * @throw Core\Exception\Message
		  */
		protected function _load($filename)
		{
			if(file_exists($filename))
			{
				if(is_readable($filename))
				{
					$json = file_get_contents($filename);

					if($json !== false)
					{
						// @todo php 7.3
						//$datas = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
						$datas = json_decode($json, true);

						if($datas !== null) {
							return $datas;
						}
						else {
							throw new E\Message("Le fichier de sauvegarde '".$filename."' n'a pas une structure JSON valide", E_USER_ERROR);
						}
					}
					else {
						throw new E\Message("Le contenu du fichier de sauvegarde '".$filename."' n'a pas pu être récupéré", E_USER_ERROR);
					}
				}
				else {
					throw new E\Message("Le fichier de sauvegarde '".$filename."' ne peut être lu", E_USER_ERROR);
				}
			}
			else {
				throw new E\Message("Le fichier de sauvegarde '".$filename."' n'existe pas", E_USER_ERROR);
			}
		}

		/**
		  * @param array $configs Configurations to save
		  * @param string $filename Configuration filename
		  * @return bool
		  * @throw Core\Exception\Message
		  */
		protected function _save(array $configs, $filename)
		{
			$status = false;

			$fileExists = file_exists($filename);
			$pathname = pathinfo($filename, PATHINFO_DIRNAME);
			$pathname = C\Tools::pathname($pathname, true, true);		// Permet juste le mkdir

			if((!$fileExists && is_writable($pathname)) || ($fileExists && is_writable($filename)))
			{
				// @todo php 7.3
				//$json = json_encode($configs, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
				$json = json_encode($configs, JSON_PRETTY_PRINT);

				if($json !== false) {
					$status = file_put_contents($filename, $json, LOCK_EX);
					return ($status !== false);
				}
				else {
					throw new E\Message("Une erreur s'est produite durant la génération du JSON de la configuration", E_USER_ERROR);
				}
			}
			else {
				$eMessage = "Impossible de sauvegarder la configuration dans '".$filename."'.".PHP_EOL;
				$eMessage .= "Vérifiez les droits d'écriture du fichier et le chemin '".$pathname."'";
				throw new E\Message($eMessage, E_USER_ERROR);
			}

			return $status;
		}

		/**
		  * @param array $configs Configuration
		  * @param bool $keepName Keep name or allow to rewrite it
		  * @param string $prefix Rule name prefix
		  * @param string $suffix Rule name suffix
		  * @return false|int Number of rules imported
		  * @throw Core\Exception\Message
		  */
		protected function _import(array $configs, $keepName, $prefix, $suffix)
		{
			$counterS = $this->_importSites($configs, true);
			$counterR = $this->_importRules($configs, $keepName, $prefix, $suffix, true);

			return ($counterS !== false && $counterR !== false) ? ($counterR) : (false);
		}

		/**
		  * @param array $addresses Addresses configuration
		  * @param bool $checkValidity
		  * @return int Number of addresses imported
		  * @throw Core\Exception\Message
		  */
		protected function _importAddresses(array $addresses, $checkValidity)
		{
			$counter = 0;

			foreach($addresses as $type => $_addresses)
			{
				if($this->_addressFwProgram->isType($type)) {
					$results = $this->_addressFwProgram->restore($type, $_addresses, $checkValidity);
					$counter += count($results);
				}
			}

			return $counter;
		}

		/**
		  * @param array $sites Sites configuration
		  * @param bool $checkValidity
		  * @return int Number of sites imported
		  * @throw Core\Exception\Message
		  */
		protected function _importSites(array $sites, $checkValidity)
		{
			$counter = 0;

			foreach($sites as $type => $_sites)
			{
				if($this->_siteFwProgram->isType($type)) {
					$results = $this->_siteFwProgram->restore($type, $_sites, $checkValidity);
					$counter += count($results);
				}
			}

			return $counter;
		}

		/**
		  * @param array $rules Rules configuration
		  * @param bool $keepName Keep name or allow to rewrite it
		  * @param string $prefix Rule name prefix
		  * @param string $suffix Rule name suffix
		  * @param bool $checkValidity
		  * @return int Number of rules imported
		  * @throw Core\Exception\Message
		  */
		protected function _importRules(array $rules, $keepName, $prefix, $suffix, $checkValidity)
		{
			$counter = 0;

			foreach($rules as $type => $_rules)
			{
				if(($ruleClass = $this->_ruleFwProgram->getClass($type)) !== false)
				{
					if(!$keepName) {
						$baseRuleName = $this->_ruleFwProgram->getNextName($type);
					}

					foreach($_rules as $index => &$rule)
					{
						if(!C\Tools::is('string&&!empty', $prefix)) $prefix = false;
						if(!C\Tools::is('string&&!empty', $suffix)) $suffix = false;

						if($keepName) {
							$name = $rule[$ruleClass::FIELD_NAME];
						}
						else {
							$name = $baseRuleName + $index;
						}

						$name = $prefix.$name.$suffix;
						$rule[$ruleClass::FIELD_NAME] = $name;

						foreach(array('source' => 'sources', 'destination' => 'destinations') as $attribute => $attributes)
						{
							if(array_key_exists($attributes, $rule))
							{
								foreach($rule[$attributes] as &$addressObject)
								{
									$addressParts = explode($ruleClass::SEPARATOR_TYPE, $addressObject, 2);

									if(count($addressParts) === 2)
									{
										// @todo temporaire/compatibilité
										// Permet le changement de key a type
										// ------------------------------
										$addressType = array_search($addressParts[0], $this->_addressFwProgram::OBJECT_KEYS, false);

										if($addressType === false) {
											$addressType = $addressParts[0];
										}
										// ------------------------------

										if($this->_addressFwProgram->isType($addressType))
										{
											$Core_Api_Address = $this->_addressFwProgram->getObject($addressType, $addressParts[1]);

											if($Core_Api_Address !== false) {
												$addressObject = $Core_Api_Address;
											}
											else {
												throw new E\Message("L'adresse '".$addressObject."' n'existe pas", E_USER_ERROR);
											}
										}
										else {
											throw new E\Message("L'adresse '".$addressObject."' n'est pas valide (type)", E_USER_ERROR);
										}
									}
									else {
										throw new E\Message("L'adresse '".$addressObject."' n'est pas valide (format)", E_USER_ERROR);
									}
								}
								unset($addressObject);
							}
						}
					}
					unset($rule);

					$results = $this->_ruleFwProgram->restore($type, $_rules, $checkValidity);
					$counter += count($results);

					foreach($results as $Core_Api_Rule)
					{
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
					}
				}
			}

			return $counter;
		}

		/**
		  * @param array $configs Configurations to export
		  * @return array
		  */
		protected function _export(array $configs)
		{
			return $configs;
		}
	}