<?php
	namespace App\Firewall;

	use ArrayObject;

	use Core as C;
	use Core\Exception as E;

	use Cli as Cli;

	use App\Firewall\Core;

	class Shell_Program_Firewall_Config extends Shell_Program_Firewall_Abstract
	{
		const OBJECT_IDS = array(
			Core\Api_Host::OBJECT_TYPE,
			Core\Api_Subnet::OBJECT_TYPE,
			Core\Api_Network::OBJECT_TYPE
		);

		const OBJECT_KEYS = array(
			Core\Api_Host::OBJECT_TYPE => Core\Api_Host::OBJECT_KEY,
			Core\Api_Subnet::OBJECT_TYPE => Core\Api_Subnet::OBJECT_KEY,
			Core\Api_Network::OBJECT_TYPE => Core\Api_Network::OBJECT_KEY
		);

		const OBJECT_CLASSES = array(
			Core\Api_Host::OBJECT_TYPE => 'App\Firewall\Core\Api_Host',
			Core\Api_Subnet::OBJECT_TYPE => 'App\Firewall\Core\Api_Subnet',
			Core\Api_Network::OBJECT_TYPE => 'App\Firewall\Core\Api_Network'
		);

		const CONFIG_IDS = array(
			Core\Api_Site::OBJECT_TYPE,
			Core\Api_Rule::OBJECT_TYPE
		);

		const CONFIG_KEYS = array(
			Core\Api_Site::OBJECT_TYPE => Core\Api_Site::OBJECT_KEY,
			Core\Api_Rule::OBJECT_TYPE => Core\Api_Rule::OBJECT_KEY
		);

		const CONFIG_CLASSES = array(
			Core\Api_Site::OBJECT_TYPE => 'App\Firewall\Core\Api_Site',
			Core\Api_Rule::OBJECT_TYPE => 'App\Firewall\Core\Api_Rule'
		);

		const IMPORT_CLASSES = array(
			'csv' => 'App\Firewall\Shell_Program_Firewall_Config_Extension_Csv',
		);

		/**
		  * @var Cli\Terminal\Main
		  */
		protected $_TERMINAL;

		/**
		  * @var Cli\Shell\Main
		  */
		protected $_SHELL;

		/**
		  * @var Core\Config
		  */
		protected $_CONFIG;

		/**
		  * @var ArrayObject
		  */
		protected $_objects;

		/**
		  * @var bool
		  */
		protected $_hasChanges = false;

		/**
		  * @var bool
		  */
		protected $_isSaving = false;

		/**
		  * @var bool
		  */
		protected $_isAutoSaving = false;

		/**
		  * @var string
		  */
		protected $_filename = null;


		public function __construct(Cli\Shell\Main $SHELL, ArrayObject $objects)
		{
			$this->_SHELL = $SHELL;
			$this->_TERMINAL = $SHELL->terminal;
			$this->_CONFIG = $SHELL->config;

			$this->_objects = $objects;
		}

		protected function _canLoad()
		{
			return ($this->_filename === null);
		}

		public function hasChanges()
		{
			$this->_isSaving = false;
			$this->_isAutoSaving = false;
			$this->_hasChanges = true;

			$this->autosave();
			return $this;
		}

		protected function _isSaving()
		{
			$this->_isSaving = true;
			$this->_isAutoSaving = false;
			$this->_hasChanges = false;

			$this->_resetAutosave();
			return $this;
		}

		protected function _isAutoSaving()
		{
			$this->_isAutoSaving = true;
			return $this;
		}

		protected function _resetAutosave()
		{
			$filename = $this->_CONFIG->FIREWALL->configuration->paths->autosave;
			$filename = C\Tools::filename($filename);

			if(file_exists($filename) && is_writable($filename)) {
				return unlink($filename);
			}
			else {
				return false;
			}
		}

		protected function _clearObjects()
		{
			foreach(self::OBJECT_KEYS as $key) {
				$objects =& $this->_objects[$key];		// /!\ Important
				$objects = array();
			}
		}

		protected function _clearConfigs()
		{
			foreach(self::CONFIG_KEYS as $key) {
				$objects =& $this->_objects[$key];		// /!\ Important
				$objects = array();
			}
		}

		protected function _getObjectsToSave()
		{
			$items = array();
			$errors = array();

			foreach($this->_objects as $key => $objects)
			{
				if(($type = $this->_addressKeyToType($key)) !== false) {
					$name = 'objects';
				}
				elseif(($type = $this->_configKeyToType($key)) !== false) {
					$name = 'configs';
				}
				else {
					throw new Exception("Object key '".$key."' is not valid", E_USER_ERROR);
				}

				$items[$name][$type] = array();

				foreach($objects as $object)
				{
					if($object->isValid()) {
						$items[$name][$type][] = $object->sleep();
					}
					else {
						$errors[] = $object;
					}
				}
			}

			return array($items, $errors);
		}

		// LOAD
		// --------------------------------------------------
		protected function _loadAddresses(array $addresses)
		{
			$status = true;

			foreach($addresses as $type => $_addresses)
			{
				if(($addressApiClass = $this->_addressTypeToClass($type, false)) !== false)
				{
					foreach($_addresses as $address)
					{
						$Core_Api_Address = new $addressApiClass();
						$status = $Core_Api_Address->wakeup($address);

						if($status && $Core_Api_Address->isValid()) {
							$this->_objects[$addressApiClass::OBJECT_KEY][$Core_Api_Address->name] = $Core_Api_Address;
						}
						else {
							$status = false;
							break(2);
						}
					}
				}
				else {
					throw new Exception("Unknown address type '".$type."'", E_USER_ERROR);
				}
			}

			return $status;
		}

		protected function _loadConfigurations(array $configs, $loadSite = true, $loadRules = true)
		{
			$status = true;

			if($loadSite && array_key_exists(Core\Api_Site::OBJECT_TYPE, $configs))
			{
				$sites = $configs[Core\Api_Site::OBJECT_TYPE];

				if(count($sites) > 0)
				{
					foreach($sites as $site)
					{
						$Core_Api_Site = new Core\Api_Site();
						$status = $Core_Api_Site->wakeup($site);

						if($status)
						{
							if($Core_Api_Site->isValid()) {
								$name = $Core_Api_Site->name;
								$this->_objects[Core\Api_Site::OBJECT_KEY][$name] = $Core_Api_Site;
							}
							else {
								throw new E\Message("Le site '".$site['name']."' semble invalide et bloque le chargement de la configuration", E_USER_ERROR);
								$status = false;
								break;
							}
						}
						else {
							throw new E\Message("Le site '".$site['name']."' n'existe pas ou sa configuration est absente", E_USER_ERROR);
							break;
						}
					}
				}
			}

			if($status && $loadRules && array_key_exists(Core\Api_Rule::OBJECT_TYPE, $configs))
			{
				$rules = $configs[Core\Api_Rule::OBJECT_TYPE];

				if(count($rules) > 0)
				{
					foreach($rules as $index => $rule)
					{
						/**
						  * Permet de garantir l'unicité des noms des règles
						  * Permet de garantir l'idempotence lors de l'export
						  */
						$ruleName = $rule[Core\Api_Rule::FIELD_NAME];
						$ruleId = $ruleName-1;

						if(!array_key_exists($ruleId, $this->_objects[Core\Api_Rule::OBJECT_KEY]))
						{
							$Core_Api_Rule = new Core\Api_Rule();

							try {
								$status = $Core_Api_Rule->wakeup($rule, $this->_objects);
							}
							catch(E\Message $exception) {
								$status = false;
							}

							if($status)
							{
								if($Core_Api_Rule->isValid()) {
									$this->_objects[Core\Api_Rule::OBJECT_KEY][$ruleId] = $Core_Api_Rule;
								}
								else {
									$invalidFieldNames = $Core_Api_Rule->isValid(true);
									throw new E\Message("La règle '".$ruleName."' semble invalide et bloque le chargement de la configuration (".implode(', ', $invalidFieldNames).")", E_USER_ERROR);
								}
							}
							elseif(isset($exception)) {
								throw new E\Message("La règle '".$ruleName."' possède des attributs incorrects:".PHP_EOL.$exception->getMessage(), E_USER_ERROR);
							}
							else {
								throw new E\Message("Impossible de charger la règle '".$ruleName."'", E_USER_ERROR);
							}
						}
						else {
							throw new E\Message("La règle '".$ruleName."' existe déjà", E_USER_ERROR);
						}
					}

					/**
					  * Sécurité afin de s'assurer que l'ordre des règles est correct
					  */
					ksort($this->_objects[Core\Api_Rule::OBJECT_KEY]);
				}
			}

			return $status;
		}

		protected function _recovery()
		{
			$status = false;
			$config = $this->_CONFIG->FIREWALL->configuration;

			if($config->autosave->status)
			{
				$filename = $config->paths->autosave;
				$filename = C\Tools::filename($filename);

				if((file_exists($filename) && is_readable($filename)))
				{
					$this->_SHELL->EOL();

					$Cli_Terminal_Question = new Cli\Terminal\Question();

					$question = "Souhaitez-vous charger le fichier d'autosauvegarde? [Y|n]";
					$question = C\Tools::e($question, 'orange', false, false, true);
					$answer = $Cli_Terminal_Question->question($question);
					$answer = mb_strtolower($answer);

					if($answer === '' || $answer === 'y' || $answer === 'yes')
					{
						$json = file_get_contents($filename);

						if($json !== false)
						{
							// @todo php 7.3
							//$items = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
							$items = json_decode($json, true);

							if($items !== null)
							{
								try
								{
									$statusA = $this->_loadAddresses($items['objects']);

									if($statusA) {
										$statusC = $this->_loadConfigurations($items['configs']);
									}
								}
								catch(\Exception $e) {
									$this->_SHELL->throw($e);
									$statusA = false;
									$statusC = false;
								}

								if(!$statusA || !$statusC) {
									$this->_clearObjects();
									$this->_clearConfigs();

									$this->_SHELL->error("Impossible de récupérer la sauvegarde automatique!", 'red');
								}
								else
								{
									/**
									  * /!\ Important, permet de bloquer un futur chargement
									  * $this->_filename doit toujours être le fichier JSON
									  */
									$this->_filename = $filename;
									$this->_SHELL->print("Récupération de la sauvegarde automatique terminée!", 'green');
								}

								/**
								  * Le fichier autosave existant alors même si il est vide on a bien essayé de la charger
								  * donc il faut l'indiquer en retournant true et même si une erreur s'est produite
								  */
								$status = true;
							}
						}
					}
				}
			}
			else {
				$this->_SHELL->error("/!\ La sauvegarde automatique est désactivée !", 'red');
			}

			return $status;
		}

		public function autoload()
		{
			$status = $this->_recovery();

			if(!$status)
			{
				$status = false;
				$filename = $this->_CONFIG->FIREWALL->configuration->paths->objects;
				$filename = C\Tools::filename($filename);

				if(file_exists($filename))
				{
					if(is_readable($filename))
					{
						$json = file_get_contents($filename);

						if($json !== false)
						{
							// @todo php 7.3
							//$items = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
							$items = json_decode($json, true);

							if($items !== null)
							{
								try {
									$status = $this->_loadAddresses($items);
								}
								catch(\Exception $e) {
									$this->_SHELL->throw($e);
									$status = false;
								}

								if($status) {
									$this->_SHELL->print("Chargement des objets terminée!", 'green');
								}
								else {
									$this->_clearObjects();
									$this->_SHELL->error("Une erreur s'est produite pendant le chargement des objets", 'orange');
								}
							}
							else {
								$this->_SHELL->error("Le fichier de sauvegarde '".$filename."' n'a pas une structure JSON valide", 'orange');
							}
						}
						else {
							$this->_SHELL->error("Une erreur s'est produite pendant la lecture du fichier de sauvegarde '".$filename."'", 'orange');
						}
					}
					else {
						$this->_SHELL->error("Le fichier de sauvegarde '".$filename."' ne peut être lu", 'orange');
					}
				}
				else {
					$status = true;
				}
			}

			$this->_SHELL->EOL();
			return $status;
		}

		public function load(array $args)
		{
			$status = false;

			if(isset($args[0]))
			{
				if($this->_canLoad())
				{
					$loadJsonSites = true;
					$loadJsonRules = true;

					$pathname = $this->_CONFIG->FIREWALL->configuration->paths->configs;
					$filename = C\Tools::filename(rtrim($pathname, '/').'/'.$args[0].'.json');

					if(preg_match('#\.([^.\s]*)$#i', $args[0], $matches))
					{
						$filenameLength = (mb_strlen($args[0])-mb_strlen($matches[1])-1);
						$args[1] = mb_substr($args[0], 0, $filenameLength);					// filename
						$args[0] = mb_strtolower($matches[1]);								// format
					}
					else {
						$args[1] = $args[0];												// filename
						$args[0] = 'json';													// format
					}
						
					$filename = C\Tools::filename(rtrim($pathname, '/').'/'.$args[1].'.json');

					if(array_key_exists($args[0], self::IMPORT_CLASSES))
					{
						$loadJsonSites = true;
						$loadJsonRules = false;

						$Shell_Program_Firewall_Config_Interface = self::IMPORT_CLASSES[$args[0]];
						$Shell_Program_Firewall_Config_Interface = new $Shell_Program_Firewall_Config_Interface($this->_SHELL, $this->_objects);

						try {
							$counter = $Shell_Program_Firewall_Config_Interface->load($filename);
						}
						catch(\Exception $e) {
							$this->_SHELL->throw($e);
							$counter = -1;
						}

						$this->_SHELL->EOL();

						switch($counter)
						{
							case -1: {
								$this->_SHELL->error("Une erreur s'est produite pendant le chargement de la configuration '".$args[1]."'", 'orange');
								$this->_clearConfigs();
								return false;
							}
							case 0:
							case 1: {
								$this->_SHELL->print($counter." règle a été chargée", 'green');
								break;
							}
							default: {
								$this->_SHELL->print($counter." règles ont été chargées", 'green');
							}
						}
					}
					elseif($args[0] !== 'json') {
						$this->_SHELL->error("Le format '".$args[0]."' du fichier à charger n'est pas supporté", 'orange');
						return false;
					}

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

								if($datas !== null)
								{
									try {
										$status = $this->_loadConfigurations($datas, $loadJsonSites, $loadJsonRules);
									}
									catch(\Exception $e) {
										$this->_SHELL->throw($e);
										$status = false;
									}

									if($status) {
										$this->_filename = $filename;		// Toujours extension JSON
										$this->_SHELL->print("Chargement de la configuration '".$args[1]."' terminée!", 'green');
									}
									else {
										$this->_clearConfigs();
										$this->_SHELL->error("Une erreur s'est produite pendant le chargement de la configuration '".$filename."'", 'orange');
									}
								}
								else {
									$this->_SHELL->error("Le fichier de sauvegarde '".$filename."' n'a pas une structure JSON valide", 'orange');
								}
							}
							else {
								$this->_SHELL->error("Une erreur s'est produite pendant la lecture du fichier de sauvegarde '".$filename."'", 'orange');
							}
						}
						else {
							$this->_SHELL->error("Le fichier de sauvegarde '".$filename."' ne peut être lu", 'orange');
						}
					}
					else {
						$this->_SHELL->error("Le fichier de sauvegarde '".$filename."' n'existe pas", 'orange');
					}
				}
				else {
					$this->_SHELL->error("Un fichier de sauvegarde '".$this->_filename."' a déjà été chargé", 'orange');
				}
			}

			return $status;
		}
		// --------------------------------------------------

		// SAVE
		// --------------------------------------------------
		public function autosave()
		{
			$config = $this->_CONFIG->FIREWALL->configuration;

			if($config->autosave->status && !$this->isSaving && !$this->isAutoSaving && $this->hasChanges)
			{
				$status = false;
				$filename = $config->paths->autosave;
				$filename = C\Tools::filename($filename);

				$pathname = pathinfo($filename, PATHINFO_DIRNAME);

				if((!file_exists($filename) && is_writable($pathname)) || (file_exists($filename) && is_writable($filename)))
				{
					try {
						list($items,) = $this->_getObjectsToSave();
					}
					catch(E\Message $e) {
						$this->_SHELL->error("[AUTOSAVE] ".$e->getMessage(), 'orange');
						return true;
					}

					if(count($items) > 0)
					{
						// @todo php 7.3
						//$json = json_encode($items, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
						$json = json_encode($items, JSON_PRETTY_PRINT);

						if($json !== false)
						{
							$status = file_put_contents($filename, $json, LOCK_EX);

							if($status !== false) {
								$this->_isAutoSaving();
							}
							else {
								$this->_SHELL->error("[AUTOSAVE] Une erreur s'est produite pendant la sauvegarde du fichier de configuration '".$filename."'", 'orange');
							}
						}
						else {
							$this->_SHELL->error("[AUTOSAVE] Une erreur s'est produite pendant l'encodage de la configuration en JSON", 'orange');
						}
					}
					else {
						return true;
					}
				}
				else {
					$this->_SHELL->error("[AUTOSAVE] Le dossier de sauvegarde '".$pathname."' ne peut être modifié", 'orange');
				}

				return $status;
			}
			else {
				return true;
			}
		}

		public function save(array $args)
		{
			$status = false;
			$filename = $this->_CONFIG->FIREWALL->configuration->paths->objects;
			$filename = C\Tools::filename($filename);

			$pathname = pathinfo($filename, PATHINFO_DIRNAME);

			if((!file_exists($filename) && is_writable($pathname)) || (file_exists($filename) && is_writable($filename)))
			{
				try {
					list($items, $errObjects) = $this->_getObjectsToSave();
				}
				catch(\Exception $e) {
					$this->_SHELL->throw($e);
					return true;
				}

				if(count($errObjects) > 0)
				{
					foreach($errObjects as $errObject){
						$this->_SHELL->error("L'objet ".$errObject::OBJECT_NAME." '".$errObjects->name."' n'est pas valide", 'orange');
					}

					return true;
				}
				elseif(array_key_exists('objects', $items))
				{
					// @todo php 7.3
					//$json = json_encode($items['objects'], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
					$json = json_encode($items['objects'], JSON_PRETTY_PRINT);

					if($json !== false)
					{
						$status = file_put_contents($filename, $json, LOCK_EX);

						if($status !== false)
						{
							$this->_SHELL->print("Sauvegarde des objets terminée! (".$filename.")", 'green');
							unset($filename);	// /!\ Important

							if(isset($args[0]))
							{
								$pathname = $this->_CONFIG->FIREWALL->configuration->paths->configs;
								$filename = C\Tools::filename(rtrim($pathname, '/').'/'.$args[0].'.json');

								if($this->_filename !== null && $this->_filename === $filename) {
									$args[1] = 'force';
								}
							}
							elseif($this->_filename !== null) {
								$filename = $this->_filename;
								$args[0] = basename($this->_filename, '.json');
								$args[1] = 'force';
							}

							if(isset($filename))
							{
								$fileExists = file_exists($filename);

								if(!$fileExists || (isset($args[1]) && $args[1] === 'force'))
								{
									$pathname = pathinfo($filename, PATHINFO_DIRNAME);

									if((!$fileExists && is_writable($pathname)) || ($fileExists && is_writable($filename)))
									{
										if(array_key_exists('configs', $items))
										{
											// @todo php 7.3
											//$json = json_encode($items['configs'], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
											$json = json_encode($items['configs'], JSON_PRETTY_PRINT);

											if($json !== false) {
												$status = file_put_contents($filename, $json, LOCK_EX);
												$toolSaveStatus = ($status !== false);
											}
											else {
												$toolSaveStatus = false;
											}

											$Shell_Program_Firewall_Config_Extension_Csv = new Shell_Program_Firewall_Config_Extension_Csv($this->_SHELL, $this->_objects);
											$adminSaveStatus = $Shell_Program_Firewall_Config_Extension_Csv->save($filename, $items['configs']);

											if($toolSaveStatus && $adminSaveStatus) {												
												$this->_isSaving();
												$this->_SHELL->print("Sauvegarde de la configuration '".$args[0]."' terminée!", 'green');
											}
											else {
												$this->_SHELL->error("Une erreur s'est produite pendant la sauvegarde du fichier de configuration '".$filename."'", 'orange');
											}
										}
									}
									else {
										$this->_SHELL->error("Impossible de sauvegarder la configuration dans '".$filename."'", 'orange');
									}
								}
								else {
									$this->_SHELL->error("Le fichier de sauvegarde '".$filename."' existe déjà. Pour l'écraser utilisez l'argument 'force'", 'orange');
								}
							}
							else {
								$this->_SHELL->error("Merci d'indiquer le nom du fichier de sauvegarde", 'orange');
							}
						}
						else {
							$this->_SHELL->error("Une erreur s'est produite pendant l'écriture du fichier de sauvegarde '".$filename."'", 'orange');
						}
					}
					else {
						$this->_SHELL->error("Une erreur s'est produite pendant l'encodage des objets en JSON", 'orange');
					}
				}
			}
			else {
				$this->_SHELL->error("Impossible de sauvegarder les objets dans '".$filename."'", 'orange');
			}

			return $status;
		}
		// --------------------------------------------------

		public function import(array $firewalls, $type, array $args)
		{
			$status = true;

			if(isset($args[0]))
			{
				if(array_key_exists($args[0], self::IMPORT_CLASSES))
				{
					if(isset($args[1]))
					{
						$filename = $args[1];
						$pathParts = pathinfo($filename);

						if($pathParts['dirname'] !== '.')
						{
							$pathname = realpath($pathParts['dirname']);

							if($pathname !== false) {
								$filename = $pathname.'/'.$pathParts['basename'];
							}
						}

						if(file_exists($filename) && is_readable($filename) && is_file($filename))
						{
							if($this->_isSaving || !$this->_hasChanges || (isset($args[2]) && $args[2] === 'force'))
							{
								$Shell_Program_Firewall_Config_Interface = self::IMPORT_CLASSES[$args[0]];
								$Shell_Program_Firewall_Config_Interface = new $Shell_Program_Firewall_Config_Interface($this->_SHELL, $this->_objects);
								
								try {
									$counter = $Shell_Program_Firewall_Config_Interface->import($filename);
								}
								catch(\Exception $e) {
									$this->_SHELL->throw($e);
									$counter = -1;
								}

								switch($counter)
								{
									case -1: {
										$status = false;
										break;
									}
									case 0:
									case 1: {
										$this->_SHELL->print($counter." règle a été importée", 'green');
										break;
									}
									default: {
										$this->_SHELL->print($counter." règles ont été importées", 'green');
									}
								}

								if($status) {
									$this->_SHELL->print("Importation de la configuration '".$filename."' terminée!", 'green');
								}
								else {
									$this->_clearConfigs();
									$this->_SHELL->error("Une erreur s'est produite pendant l'importation de la configuration '".$filename."'", 'orange');
								}
							}
							else {
								$this->_SHELL->error("Il est vivement recommandé de sauvegarder la configuration avant d'en importer une autre. Pour importer malgrés tout utilisez l'argument 'force'", 'orange');
							}
						}
						else {
							$this->_SHELL->error("Le fichier à importer '".$filename."' n'existe pas ou ne peut être lu", 'orange');
						}

						return true;
					}
					else {
						$this->_SHELL->error("Fichier à importer manquant", 'orange');
					}
				}
				else {
					$this->_SHELL->error("Le format '".$args[0]."' du fichier à importer n'est pas supporté", 'orange');
				}
			}

			return false;
		}

		public function export(array $firewalls, $type, array $args)
		{
			if(isset($args[0]))
			{
				$format = $args[0];
				$force = (isset($args[1]) && $args[1] === 'force');

				$Shell_Program_Firewall_Config_Helper_Export = new Shell_Program_Firewall_Config_Helper_Export($this->_SHELL, $this, $this->_objects);
				$Shell_Program_Firewall_Config_Helper_Export->export($firewalls, $type, $format, $force);

				return true;
			}

			return false;
		}

		public function copy(array $firewalls, $type, array $args)
		{
			if(isset($args[0]) && isset($args[1]) && isset($args[2]))
			{
				$format = $args[0];
				$method = $args[1];
				$site = $args[2];

				$Shell_Program_Firewall_Config_Helper_Export = new Shell_Program_Firewall_Config_Helper_Export($this->_SHELL, $this, $this->_objects);
				$Shell_Program_Firewall_Config_Helper_Export->copy($firewalls, $type, $format, $method, $site);

				return true;
			}

			return false;
		}

		// TOOLS
		// --------------------------------------------------
		protected function _addressTypeToKey($type)
		{
			return $this->_typeToKey($type);
		}

		protected function _addressTypeToClass($type)
		{
			return $this->_typeToClass($type);
		}

		protected function _addressKeyToType($key)
		{
			return $this->_keyToType($key);
		}

		protected function _addressClassToType($class)
		{
			return $this->_classToType($class);
		}

		protected function _configKeyToType($key)
		{
			$types = array_keys(static::CONFIG_KEYS, $key, true);
			return (count($types) === 1) ? (current($types)) : (false);
		}

		protected function _configClassToType($class)
		{
			$types = array_keys(static::CONFIG_CLASSES, $class, true);
			return (count($types) === 1) ? (current($types)) : (false);
		}
		// --------------------------------------------------

		public function __get($name)
		{
			switch($name)
			{
				case 'isSaving': {
					return $this->_isSaving;
				}
				case 'isAutoSaving': {
					return $this->_isAutoSaving;
				}
				case 'hasChanges': {
					return $this->_hasChanges;
				}
				default: {
					throw new Exception("This attribute '".$name."' does not exist", E_USER_ERROR);
				}
			}
		}
	}