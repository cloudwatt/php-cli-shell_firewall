<?php
	class Service_Shell_Firewall_Config
	{
		const EXPORT_FORMAT_CLASS = array(
			'junos' => 'Firewall_Template_Junos',
			'junos_set' => 'Firewall_Template_Junos_Set',
		);

		protected $_MAIN;
		protected $_CONFIG;

		protected $_objects;

		protected $_isSaving = false;
		protected $_hasChanges = false;


		public function __construct(Service_Abstract $MAIN, ArrayObject $objects)
		{
			$this->_MAIN = $MAIN;
			$this->_CONFIG = CONFIG::getInstance();

			$this->_objects = $objects;
		}

		public function hasChanges()
		{
			$this->_hasChanges = true;
			$this->_isSaving = false;
			return $this;
		}

		protected function _isSaving()
		{
			$this->_isSaving = true;
			$this->_hasChanges = false;
			return $this;
		}

		public function autoload()
		{
			$filename = $this->_CONFIG->FIREWALL->configuration->objects->file;
			$filename = Tools::filename($filename);
			$status = false;

			if(file_exists($filename))
			{
				if(is_readable($filename))
				{
					$json = file_get_contents($filename);

					if($json !== false)
					{
						$items = json_decode($json, true);

						if($items !== null)
						{
							foreach($items as $type => $objects)
							{
								switch($type)
								{
									case Firewall_Api_Host::OBJECT_TYPE: {
										$class = 'Firewall_Api_Host';
										break;
									}
									case Firewall_Api_Subnet::OBJECT_TYPE: {
										$class = 'Firewall_Api_Subnet';
										break;
									}
									case Firewall_Api_Network::OBJECT_TYPE: {
										$class = 'Firewall_Api_Network';
										break;
									}
									default: {
										throw new Exception("Unknown type '".$type."'", E_USER_ERROR);
									}
								}

								foreach($objects as $object)
								{
									$objectApi = new $class();
									$status = $objectApi->wakeup($object);

									if($status)
									{
										if($objectApi->isValid()) {
											$name = $objectApi->name;
											$this->_objects[$class][$name] = $objectApi;
										}
										else {
											$status = false;
											break(2);
										}
									}
									else {
										break(2);
									}
								}
							}

							if($status) {
								$this->_MAIN->print("Chargement des objets terminée!", 'green');
							}
							else {
								$this->_MAIN->error("Une erreur s'est produite pendant le chargement des objets", 'orange');
							}
						}
						else {
							$this->_MAIN->error("Le fichier de sauvegarde '".$filename."' n'a pas une structure JSON valide", 'orange');
						}
					}
					else {
						$this->_MAIN->error("Une erreur s'est produite pendant la lecture du fichier de sauvegarde '".$filename."'", 'orange');
					}
				}
				else {
					$this->_MAIN->error("Le fichier de sauvegarde '".$filename."' ne peut être lu", 'orange');
				}
			}
			else {
				$status = true;
			}

			$this->_MAIN->EOL();
			return $status;
		}

		public function load(array $args)
		{
			$status = false;

			if(isset($args[0]))
			{
				$pathname = $this->_CONFIG->FIREWALL->configuration->configs->path;
				$filename = Tools::filename(rtrim($pathname, '/').'/'.$args[0].'.json');

				if(file_exists($filename))
				{
					if(is_readable($filename))
					{
						$json = file_get_contents($filename);

						if($json !== false)
						{
							$datas = json_decode($json, true);

							if($datas !== null)
							{
								$sites = $datas[Firewall_Api_Site::OBJECT_TYPE];

								foreach($sites as $site)
								{
									$Firewall_Api_Site = new Firewall_Api_Site();
									$status = $Firewall_Api_Site->wakeup($site);

									if($status)
									{
										if($Firewall_Api_Site->isValid()) {
											$name = $Firewall_Api_Site->name;
											$this->_objects['Firewall_Api_Site'][$name] = $Firewall_Api_Site;
										}
										else {
											$status = false;
											break;
										}
									}
									else {
										break;
									}
								}

								if($status)
								{
									$rules = $datas[Firewall_Api_Rule::OBJECT_TYPE];

									foreach($rules as $rule)
									{
										$Firewall_Api_Rule = new Firewall_Api_Rule();
										$status = $Firewall_Api_Rule->wakeup($rule, $this->_objects);

										if($status)
										{
											if($Firewall_Api_Rule->isValid()) {
												$this->_objects['Firewall_Api_Rule'][] = $Firewall_Api_Rule;
												$Firewall_Api_Rule->name(count($this->_objects['Firewall_Api_Rule']));
												// /!\ Nom unique dans le cas de chargement multiple
											}
											else {
												$status = false;
												break;
											}
										}
										else {
											break;
										}
									}								
								}

								if($status) {
									$this->_MAIN->print("Chargement de la configuration '".$args[0]."' terminée!", 'green');
								}
								else {
									$this->_MAIN->error("Une erreur s'est produite pendant le chargement de la configuration '".$args[0]."'", 'orange');
								}
							}
							else {
								$this->_MAIN->error("Le fichier de sauvegarde '".$filename."' n'a pas une structure JSON valide", 'orange');
							}
						}
						else {
							$this->_MAIN->error("Une erreur s'est produite pendant la lecture du fichier de sauvegarde '".$filename."'", 'orange');
						}
					}
					else {
						$this->_MAIN->error("Le fichier de sauvegarde '".$filename."' ne peut être lu", 'orange');
					}
				}
				else {
					$this->_MAIN->error("Le fichier de sauvegarde '".$filename."' n'existe pas", 'orange');
				}
			}

			return $status;
		}

		public function save(array $args)
		{
			$filename = $this->_CONFIG->FIREWALL->configuration->objects->file;
			$filename = Tools::filename($filename);
			$status = false;

			$pathname = pathinfo($filename, PATHINFO_DIRNAME);

			if((!file_exists($filename) && is_writable($pathname)) || (file_exists($filename) && is_writable($filename)))
			{
				$datas = array();

				foreach($this->_objects as $class => $objects)
				{
					$name = (is_subclass_of($class, 'Firewall_Api_Address')) ? ('objects') : ('configs');
					$datas[$name][$class::OBJECT_TYPE] = array();

					foreach($objects as $object)
					{
						if($object->isValid()) {
							$datas[$name][$class::OBJECT_TYPE][] = $object->sleep();
						}
						else {
							$this->_MAIN->error("L'objet ".$class::OBJECT_NAME." '".$object->name."' n'est pas valide", 'orange');
							return true;
						}
					}
				}

				if(array_key_exists('objects', $datas))
				{
					$json = json_encode($datas['objects']);

					if($json !== false)
					{
						$status = file_put_contents($filename, $json, LOCK_EX);

						if($status !== false)
						{
							$this->_MAIN->print("Sauvegarde des objets terminée! (".$filename.")", 'green');

							if(isset($args[0]))
							{
								$pathname = $this->_CONFIG->FIREWALL->configuration->configs->path;
								$filename = Tools::filename(rtrim($pathname, '/').'/'.$args[0].'.json');

								$pathname = pathinfo($filename, PATHINFO_DIRNAME);

								if(!file_exists($filename) || (isset($args[1]) && $args[1] === 'force'))
								{
									if(is_writable($pathname))
									{
										if(array_key_exists('configs', $datas))
										{
											$json = json_encode($datas['configs']);

											if($json !== false)
											{
												$status = file_put_contents($filename, $json, LOCK_EX);

												if($status !== false) {
													$this->_isSaving();
													$this->_MAIN->print("Sauvegarde de la configuration '".$args[0]."' terminée!", 'green');
												}
												else {
													$this->_MAIN->error("Une erreur s'est produite pendant la sauvegarde du fichier de configuration '".$filename."'", 'orange');
												}
											}
											else {
												$this->_MAIN->error("Une erreur s'est produite pendant l'encodage de la configuration en JSON", 'orange');
											}
										}
									}
									else {
										$this->_MAIN->error("Le dossier de sauvegarde '".$pathname."' ne peut être modifié", 'orange');
									}
								}
								else {
									$this->_MAIN->error("Le fichier de sauvegarde '".$filename."' existe déjà. Pour l'écraser utilisez l'argument 'force'", 'orange');
								}
							}
						}
						else {
							$this->_MAIN->error("Une erreur s'est produite pendant l'écriture du fichier de sauvegarde '".$filename."'", 'orange');
						}
					}
					else {
						$this->_MAIN->error("Une erreur s'est produite pendant l'encodage des objets en JSON", 'orange');
					}
				}
			}
			else {
				$this->_MAIN->error("Impossible de sauvegarder les objets dans '".$filename."'", 'orange');
			}

			return $status;
		}

		public function export(array $firewalls, $type, array $args)
		{
			if(isset($args[0]))
			{
				if(array_key_exists($args[0], self::EXPORT_FORMAT_CLASS))
				{
					$Firewall_Template_Abstract = self::EXPORT_FORMAT_CLASS[$args[0]];

					if($type === null) {
						$sections = $Firewall_Template_Abstract::OBJECT_TYPE_SECTION;
					}
					elseif(array_key_exists($type, $Firewall_Template_Abstract::OBJECT_TYPE_SECTION)) {
						$sections = (array) $Firewall_Template_Abstract::OBJECT_TYPE_SECTION[$type];
					}
					else {
						$this->_MAIN->error("Section type '".$type."' non supporté", 'orange');
					}

					if(isset($sections))
					{
						$fwlCounter = count($firewalls);						

						if($fwlCounter > 0)
						{
							if($this->_isSaving || !$this->_hasChanges || (isset($args[1]) && $args[1] === 'force'))
							{
								$firewalls = array_values($firewalls);
								$sites = $this->_objects['Firewall_Api_Site'];

								foreach($firewalls as $index => $FIREWALL_Abstract)
								{
									$this->_MAIN->print("Préparation de la configuration pour '".$FIREWALL_Abstract->name."'", 'green');

									// /!\ On doit passer un template clean pour éviter toutes interactions négatives
									$Firewall_Template_Abstract = new $Firewall_Template_Abstract($this->_MAIN, $sites);
									$status = $Firewall_Template_Abstract->templating($FIREWALL_Abstract, $sections);

									if($status) {
										$this->_MAIN->print("Configuration disponible: '".$Firewall_Template_Abstract->export."'", 'green');
										if($index < $fwlCounter-1) { $this->_MAIN->EOL(); }
									}
									else {
										$msg = "Une erreur s'est produite durant la génération du template '".$Firewall_Template_Abstract->template."'";
										$msg .= " pour le firewall '".$FIREWALL_Abstract->name."'";
										$this->_MAIN->error($msg, 'orange');
										break;
									}
								}
							}
							else {
								$this->_MAIN->error("Il est vivement recommandé de sauvegarder la configuration avant de l'exporter. Pour l'exporter malgrés tout utilisez l'argument 'force'", 'orange');
							}
						}
						else {
							$this->_MAIN->error("Aucun site n'a été déclaré, il n'y a donc pas de configuration à exporter", 'orange');
						}
					}
				}
				else {
					$this->_MAIN->error("Format d'export '".$args[0]."' non supporté", 'orange');
				}

				return true;
			}

			return false;
		}

		public function __get($name)
		{
			switch($name)
			{
				case 'isSaving': {
					return $this->_isSaving;
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