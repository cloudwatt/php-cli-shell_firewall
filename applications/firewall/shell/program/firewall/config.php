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
			Core\Api_Network::OBJECT_TYPE,
			Core\Api_Site::OBJECT_TYPE,
			Core\Api_Rule::OBJECT_TYPE,
		);

		const OBJECT_KEYS = array(
			Core\Api_Host::OBJECT_TYPE => Core\Api_Host::OBJECT_KEY,
			Core\Api_Subnet::OBJECT_TYPE => Core\Api_Subnet::OBJECT_KEY,
			Core\Api_Network::OBJECT_TYPE => Core\Api_Network::OBJECT_KEY,
			Core\Api_Site::OBJECT_TYPE => Core\Api_Site::OBJECT_KEY,
			Core\Api_Rule::OBJECT_TYPE => Core\Api_Rule::OBJECT_KEY,
		);

		const OBJECT_CLASSES = array(
			Core\Api_Host::OBJECT_TYPE => 'App\Firewall\Core\Api_Host',
			Core\Api_Subnet::OBJECT_TYPE => 'App\Firewall\Core\Api_Subnet',
			Core\Api_Network::OBJECT_TYPE => 'App\Firewall\Core\Api_Network',
			Core\Api_Site::OBJECT_TYPE => 'App\Firewall\Core\Api_Site',
			Core\Api_Rule::OBJECT_TYPE => 'App\Firewall\Core\Api_Rule',
		);

		const ADDRESS_IDS = array(
			Core\Api_Host::OBJECT_TYPE,
			Core\Api_Subnet::OBJECT_TYPE,
			Core\Api_Network::OBJECT_TYPE
		);

		const ADDRESS_KEYS = array(
			Core\Api_Host::OBJECT_TYPE => Core\Api_Host::OBJECT_KEY,
			Core\Api_Subnet::OBJECT_TYPE => Core\Api_Subnet::OBJECT_KEY,
			Core\Api_Network::OBJECT_TYPE => Core\Api_Network::OBJECT_KEY
		);

		const ADDRESS_CLASSES = array(
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
			'json' => 'App\Firewall\Shell_Program_Firewall_Config_Extension_Json',
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
		  * @var App\Firewall\Shell_Program_Firewall_Object_Site
		  */
		protected $_siteFwProgram = null;

		/**
		  * @var App\Firewall\Shell_Program_Firewall_Object_Address
		  */
		protected $_addressFwProgram = null;

		/**
		  * @var App\Firewall\Shell_Program_Firewall_Object_Rule
		  */
		protected $_ruleFwProgram = null;

		/**
		  * @var App\Firewall\Shell_Program_Firewall_Config_Extension_Csv
		  */
		protected $_csvConfig = null;

		/**
		  * @var App\Firewall\Shell_Program_Firewall_Config_Extension_Json
		  */
		protected $_jsonConfig = null;

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
		  * Null allow to load a config file
		  * False forbid to load a config file, after a recovery
		  * String is the filename of the config after loaded it
		  *
		  * @var null|false|string Null allow to load a config, false forbid it, string is the file loaded
		  */
		protected $_filename = null;

		/**
		  * All prefix and suffix files loaded
		  * @var array
		  */
		protected $_filenames = array();

		/**
		  * Auto save filename
		  * @var string
		  */
		protected $_asFilename = null;


		public function __construct(Cli\Shell\Main $SHELL, ArrayObject $objects,
			Shell_Program_Firewall_Object_Site $siteFwProgram, Shell_Program_Firewall_Object_Address $addressFwProgram, Shell_Program_Firewall_Object_Rule $ruleFwProgram)
		{
			$this->_SHELL = $SHELL;
			$this->_TERMINAL = $SHELL->terminal;
			$this->_CONFIG = $SHELL->config;

			$this->_objects = $objects;

			$this->_siteFwProgram = $siteFwProgram;
			$this->_addressFwProgram = $addressFwProgram;
			$this->_ruleFwProgram = $ruleFwProgram;

			$this->_csvConfig = new Shell_Program_Firewall_Config_Extension_Csv($SHELL, $objects, $siteFwProgram, $addressFwProgram, $ruleFwProgram);
			$this->_jsonConfig = new Shell_Program_Firewall_Config_Extension_Json($SHELL, $objects, $siteFwProgram, $addressFwProgram, $ruleFwProgram);
		}

		protected function _canLoad($prefix = null, $suffix = null)
		{
			$filename = $this->_getFilename($prefix, $suffix);
			return ($filename === null);
		}

		protected function _isLoaded($prefix = null, $suffix = null)
		{
			return !$this->_canLoad($prefix, $suffix);
		}

		protected function _isRecovery()
		{
			return ($this->_filename === false);
		}

		protected function _resetLoad()
		{
			$this->_resetStatus();
			$this->_clearConfigurations();
			$this->_filename = null;
			$this->_filenames = array();
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
			$filename = $this->_getAsFilename();

			if($filename !== false && file_exists($filename) && is_writable($filename)) {
				return unlink($filename);
			}
			else {
				return false;
			}
		}

		protected function _resetStatus()
		{
			$this->_hasChanges = false;
			$this->_isSaving = false;
			$this->_isAutoSaving = false;
			return $this;
		}

		/**
		  * @param string $filename
		  * @param string $prefix
		  * @param string $suffix
		  * @return void
		  */
		protected function _setFilename($filename, $prefix = null, $suffix = null)
		{
			if($prefix !== null || $suffix !== null) {
				if(!C\Tools::is('string&&!empty', $prefix)) $prefix = 0;
				if(!C\Tools::is('string&&!empty', $suffix)) $suffix = 0;
				$this->_filenames[$prefix][$suffix] = $filename;
			}
			else {
				$this->_filename = $filename;
			}
		}

		/**
		  * @param string $prefix
		  * @param string $suffix
		  * @return null|string
		  */
		protected function _getFilename($prefix = null, $suffix = null)
		{
			if($prefix !== null || $suffix !== null)
			{
				$filenames = $this->_filenames;

				if(!C\Tools::is('string&&!empty', $prefix)) {
					$prefix = 0;
				}

				if(array_key_exists($prefix, $filenames)) {
					$filenames = $filenames[$prefix];
				}
				else {
					return null;
				}

				if(!C\Tools::is('string&&!empty', $suffix)) {
					$suffix = 0;
				}

				if(array_key_exists($suffix, $filenames)) {
					$filenames = $filenames[$suffix];
				}
				else {
					return null;
				}

				return $filenames;
			}
			else {
				return $this->_filename;
			}
		}

		protected function _getAsFilename()
		{
			if($this->_asFilename === null)
			{
				$CONFIG = $this->_CONFIG->FIREWALL->configuration;

				$status = $CONFIG->autosave->status;
				$filename = $CONFIG->paths->autosave;

				if($status && C\Tools::is('string&&!empty', $filename)) {
					$this->_asFilename = C\Tools::filename($filename);
				}
				else {
					$this->_asFilename = false;
				}
			}

			return $this->_asFilename;
		}

		protected function _clearAddresses()
		{
			foreach(self::ADDRESS_KEYS as $key) {
				$objects =& $this->_objects[$key];		// /!\ Important
				$objects = array();
			}
		}

		protected function _clearConfigurations()
		{
			foreach(self::CONFIG_KEYS as $key) {
				$objects =& $this->_objects[$key];		// /!\ Important
				$objects = array();
			}
		}

		protected function _checkAllObjects()
		{
			$errors = array();

			foreach($this->_objects as $key => $objects)
			{
				foreach($objects as $object)
				{
					if(!$object->isValid()) {
						$errors[] = $object;
					}
				}
			}

			return $errors;
		}

		protected function _getObjectsToSave($checkValidity = true)
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
					if(!$checkValidity || $object->isValid()) {
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
		protected function _recovery()
		{
			$status = false;
			$filename = $this->_getAsFilename();

			if($filename !== false)
			{
				if(file_exists($filename) && is_readable($filename))
				{
					$this->_SHELL->EOL();

					$Cli_Terminal_Question = new Cli\Terminal\Question();

					$question = "Souhaitez-vous charger le fichier d'autosauvegarde? [Y|n]";
					$question = C\Tools::e($question, 'orange', false, false, true);
					$answer = $Cli_Terminal_Question->question($question);
					$answer = mb_strtolower($answer);

					if($answer === '' || $answer === 'y' || $answer === 'yes')
					{
						try {
							$status = $this->_jsonConfig->apply($filename, 'objects', 'configs', 'configs', false);
						}
						catch(\Exception $e) {
							$this->_SHELL->throw($e);
							$status = false;
						}

						if(!$status) {
							$this->_clearAddresses();
							$this->_clearConfigurations();

							$this->_SHELL->error("Impossible de récupérer la sauvegarde automatique!", 'red');
						}
						else
						{
							/**
							  * /!\ Important, permet de bloquer un futur chargement
							  */
							$this->_setFilename(false);

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
					try {
						$status = $this->_jsonConfig->loadAddresses($filename);
					}
					catch(\Exception $e) {
						$this->_SHELL->throw($e);
						$status = false;
					}

					if($status) {
						$this->_SHELL->print("Chargement des objets terminée!", 'green');
					}
					else {
						$this->_clearAddresses();
						$this->_SHELL->error("Une erreur s'est produite pendant le chargement des objets", 'orange');
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
			if(isset($args[0]))
			{
				$prefix = (isset($args[1]) && C\Tools::is('string&&!empty', $args[1])) ? ($args[1]) : (false);

				if($this->_canLoad() || $prefix)
				{
					if($this->_canLoad($prefix))
					{
						if($this->isSaving || !$this->hasChanges || (isset($args[2]) && $args[2] === 'force'))
						{
							if(preg_match('#\.([^.\s]+)$#i', $args[0], $matches)) {
								$filenameLength = (mb_strlen($args[0])-mb_strlen($matches[1])-1);
								$basename = mb_substr($args[0], 0, $filenameLength);				// pathname or filename
								$format = mb_strtolower($matches[1]);								// format (extension)
							}
							else {
								$basename = $args[0];												// pathname or filename
								$format = 'json';													// format (extension)
							}

							if(array_key_exists($format, self::IMPORT_CLASSES))
							{
								$status = true;

								$pathname = $this->_CONFIG->FIREWALL->configuration->paths->configs;
								$pathname = rtrim($pathname, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;

								$filename = C\Tools::filename($basename.'.'.$format, $pathname);

								$Shell_Program_Firewall_Config_Interface = self::IMPORT_CLASSES[$format];
								$Shell_Program_Firewall_Config_Interface = new $Shell_Program_Firewall_Config_Interface($this->_SHELL, $this->_objects, $this->_siteFwProgram, $this->_addressFwProgram, $this->_ruleFwProgram);

								try {
									$counter = $Shell_Program_Firewall_Config_Interface->load($filename, $prefix);
								}
								catch(\Exception $e) {
									$this->_SHELL->throw($e);
									$counter = false;
								}

								$this->_SHELL->EOL();

								if(C\TOOLS::is('int&&>=0', $counter))
								{
									switch($counter)
									{
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
								else {
									$this->_SHELL->error("Une erreur s'est produite pendant le chargement de la configuration '".$filename."'", 'orange');
									$this->_clearConfigurations();
									return true;
								}

								$this->_setFilename($filename, $prefix);

								if($format !== 'json')
								{
									$filename = preg_replace('#\.([^.\s]+)$#i', '.json', $filename);
									//$filename = C\Tools::filename($basename.'.json', $pathname);

									try {
										$status = $this->_jsonConfig->loadSites($filename);
									}
									catch(\Exception $e) {
										$this->_SHELL->throw($e);
										$status = false;
									}

									if(!$status) {
										$this->_SHELL->error("Impossible de charger les sites de la configuration '".$filename."'", 'orange');
									}
								}

								if($status) {
									$this->_setFilename($filename);			// Toujours extension JSON
									$this->_SHELL->print("Chargement de la configuration '".$basename."' terminée!", 'green');
								}
								else {
									$this->_clearConfigurations();
									$this->_SHELL->error("Une erreur s'est produite pendant le chargement de la configuration '".$filename."'", 'orange');
								}
							}
							else {
								$this->_SHELL->error("Le format '".$format."' du fichier à charger n'est pas supporté", 'orange');
								return false;
							}
						}
						else {
							$this->_SHELL->error("Il est vivement recommandé de sauvegarder la configuration avant d'en charger une autre. Pour charger malgrés tout utilisez l'argument 'force'", 'orange');
						}
					}
					else {
						$this->_SHELL->error("Un fichier de sauvegarde '".$this->_getFilename($prefix)."' a déjà été chargé pour ce prefix '".$prefix."'. Merci d'indiquer un autre préfix ou d'importer la configuration", 'orange');
					}
				}
				elseif($this->_isRecovery()) {
					$this->_SHELL->error("Il n'est pas possible de charger une configuration après une récupération automatique sauf si vous indiquez un préfix", 'orange');
				}
				else {
					$this->_SHELL->error("Un fichier de sauvegarde '".$this->_getFilename()."' a déjà été chargé. Merci d'indiquer un préfix lors du chargement ou d'importer la configuration", 'orange');
				}

				return true;
			}

			return false;
		}
		// --------------------------------------------------

		// SAVE
		// --------------------------------------------------
		public function autosave()
		{
			$filename = $this->_getAsFilename();

			if($filename !== false && !$this->isSaving && !$this->isAutoSaving && $this->hasChanges)
			{
				$status = false;

				try {
					list($items,) = $this->_getObjectsToSave(false);
				}
				catch(E\Message $e) {
					$this->_SHELL->error("[AUTOSAVE] ".$e->getMessage(), 'orange');
					return true;
				}

				$status = $this->_jsonConfig->save($filename, $items);

				if($status) {
					$this->_isAutoSaving();
				}
				else {
					$this->_SHELL->error("[AUTOSAVE] Une erreur s'est produite pendant la sauvegarde du fichier de configuration '".$filename."'", 'orange');
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
					foreach($errObjects as $errObject) {
						$this->_SHELL->error("L'objet '".$errObject::OBJECT_NAME."' '".$errObject->name."' n'est pas valide", 'orange');
					}

					return true;
				}
				elseif(array_key_exists('objects', $items))
				{
					$status = $this->_jsonConfig->save($filename, $items['objects']);

					if($status !== false)
					{
						$this->_SHELL->print("Sauvegarde des objets terminée! (".$filename.")", 'green');
						unset($filename);	// /!\ Important

						if(array_key_exists('configs', $items))
						{
							if(isset($args[0]))
							{
								$basename = $args[0];

								$pathname = $this->_CONFIG->FIREWALL->configuration->paths->configs;
								$pathBasename = C\Tools::filename(rtrim($pathname, '/').'/'.$basename);
								$filename = $pathBasename.'.json';

								if($filename === $this->_getFilename()) {
									$args[1] = 'force';
								}
							}
							elseif($this->_isLoaded()) {
								$filename = $this->_getFilename();
								$pathBasename = mb_substr($filename, 0, -5);		// .json = 5
								$basename = basename($filename, '.json');
								$args[1] = 'force';
							}

							if(isset($filename))
							{
								if(!file_exists($filename) || (isset($args[1]) && $args[1] === 'force'))
								{
									foreach(array('json' => $this->_jsonConfig, 'csv' => $this->_csvConfig) as $format => $Config_Ext_Abstract)
									{
										$filename = $pathBasename.'.'.$format;

										try {
											$status = $Config_Ext_Abstract->save($filename, $items['configs']);
										}
										catch(E\Message $e) {
											$this->_SHELL->throw($e);
											$status = false;
										}

										if($status) {									
											$this->_SHELL->print("Sauvegarde de la configuration '".$basename."' terminée! (".$filename.")", 'green');
										}
										else {
											$this->_SHELL->error("Une erreur s'est produite pendant la sauvegarde du fichier de configuration '".$filename."'", 'orange');
											break;
										}
									}

									if($status) {
										$this->_isSaving();
									}
								}
								else {
									$this->_SHELL->error("Le fichier de sauvegarde '".$filename."' existe déjà. Pour l'écraser utilisez l'argument 'force'", 'orange');
								}
							}
							else {
								$this->_SHELL->error("Merci d'indiquer le nom du fichier de sauvegarde sans chemin ni extension. Example: myBackup", 'orange');
							}
						}
					}
					else {
						$this->_SHELL->error("Une erreur s'est produite pendant l'écriture du fichier de sauvegarde '".$filename."'", 'orange');
					}
				}
			}
			else {
				$this->_SHELL->error("Impossible de sauvegarder les objets dans '".$filename."'", 'orange');
				$this->_SHELL->error("Vérifiez les droits d'écriture du fichier et le chemin '".$pathname."'", 'orange');
			}

			return $status;
		}
		// --------------------------------------------------

		public function import(array $firewalls, $type, array $args)
		{
			$status = true;

			if(isset($args[0]))
			{
				$format = $args[0];

				if(array_key_exists($format, self::IMPORT_CLASSES))
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
							$prefix = (isset($args[2]) && C\Tools::is('string&&!empty', $args[2])) ? ($args[2]) : (null);

							if($this->isSaving || !$this->hasChanges || (isset($args[3]) && $args[3] === 'force'))
							{
								$Shell_Program_Firewall_Config_Interface = self::IMPORT_CLASSES[$format];
								$Shell_Program_Firewall_Config_Interface = new $Shell_Program_Firewall_Config_Interface($this->_SHELL, $this->_objects, $this->_siteFwProgram, $this->_addressFwProgram, $this->_ruleFwProgram);
								
								try {
									$counter = $Shell_Program_Firewall_Config_Interface->import($filename, $prefix);
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
									$this->_resetLoad();
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
					$this->_SHELL->error("Le format '".$format."' du fichier à importer n'est pas supporté", 'orange');
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

				try {
					$errObjects = $this->_checkAllObjects();
				}
				catch(\Exception $e) {
					$this->_SHELL->throw($e);
					return true;
				}

				if(count($errObjects) > 0)
				{
					foreach($errObjects as $errObject) {
						$this->_SHELL->error("L'objet '".$errObject::OBJECT_NAME."' '".$errObject->name."' n'est pas valide", 'orange');
					}
				}
				else {
					$Shell_Program_Firewall_Config_Helper_Export = new Shell_Program_Firewall_Config_Helper_Export($this->_SHELL, $this, $this->_objects);
					$Shell_Program_Firewall_Config_Helper_Export->export($firewalls, $type, $format, $force);
				}

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

				try {
					$errObjects = $this->_checkAllObjects();
				}
				catch(\Exception $e) {
					$this->_SHELL->throw($e);
					return true;
				}

				if(count($errObjects) > 0)
				{
					foreach($errObjects as $errObject) {
						$this->_SHELL->error("L'objet '".$errObject::OBJECT_NAME."' '".$errObject->name."' n'est pas valide", 'orange');
					}
				}
				else {
					$Shell_Program_Firewall_Config_Helper_Export = new Shell_Program_Firewall_Config_Helper_Export($this->_SHELL, $this, $this->_objects);
					$Shell_Program_Firewall_Config_Helper_Export->copy($firewalls, $type, $format, $method, $site);
				}

				return true;
			}

			return false;
		}

		// TOOLS
		// --------------------------------------------------
		/**
		  * @param $key string
		  * @return false|string
		  */
		protected function _addressKeyToType($key)
		{
			$types = array_keys(static::ADDRESS_KEYS, $key, true);
			return (count($types) === 1) ? (current($types)) : (false);
		}

		/**
		  * @param $key string
		  * @return false|string
		  */
		protected function _configKeyToType($key)
		{
			$types = array_keys(static::CONFIG_KEYS, $key, true);
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