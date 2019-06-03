<?php
	namespace App\Firewall;

	use Core as C;
	use Core\Network;
	use Core\Exception as E;

	use App\Firewall\Core;

	class Shell_Program_Firewall_Config_Helper_Export extends Shell_Program_Firewall_Config_Helper_Abstract
	{
		const EXPORT_FORMAT_CLASS = array(
			'cisco_asa' => 'App\Firewall\Core\Template_Cisco_Asa',
			'cisco_asa-dap' => 'App\Firewall\Core\Template_Cisco_Asa_Dap',
			'juniper_junos' => 'App\Firewall\Core\Template_Juniper_Junos',
			'juniper_junos-set' => 'App\Firewall\Core\Template_Juniper_Junos_Set',
			'web_html' => 'App\Firewall\Core\Template_Web_Html',
		);

		const COPY_METHOD = array(
			'scp' => null,
		);

		public function export(array $firewalls, $type, $format, $force)
		{
			$exports = $this->_export($firewalls, $type, $format, $force);
			return ($exports !== false);
		}

		public function copy(array $firewalls, $type, $format, $method, $site)
		{
			if(array_key_exists($site, $firewalls))
			{
				$firewalls = array($site => $firewalls[$site]);
				$exports = $this->_export($firewalls, $type, $format, true);

				if($exports !== false)
				{
					$this->_SHELL->EOL();

					if(array_key_exists($site, $exports))
					{
						$exportFile = $exports[$site];

						if(array_key_exists($method, self::COPY_METHOD))
						{
							$sitesConfig = $this->_CONFIG->FIREWALL->sites;

							if(isset($sitesConfig->{$site}))
							{
								$siteConfig = $sitesConfig->{$site};
								unset($sitesConfig);

								switch($method)
								{
									case 'scp':
									{
										if($siteConfig->scp === true)
										{
											$sshIp = $siteConfig->ip;
											$sshPort = $siteConfig->ssh_remotePort;
											$sshOptions = null;

											if($sshIp !== false && $sshPort !== false)
											{
												$sshBastionHost = $siteConfig->ssh_bastionHost;
												$sshBastionPort = $siteConfig->ssh_bastionPort;
												$sshPortForwarding = $siteConfig->ssh_portForwarding;

												if($sshBastionHost !== false && $sshBastionPort !== false && $sshPortForwarding !== false)
												{
													list($sshSysLogin, $sshSysPassword) = $this->_getCredentials($siteConfig, 'ssh');

													if($sshSysLogin !== false)
													{
														$bastionSSH = new Network\Ssh($sshIp, $sshPort, $sshBastionHost, $sshBastionPort, $sshPortForwarding);

														if($sshSysPassword === false) {
															$bastionSSH->useSshAgent($sshSysLogin);
														}
														else {
															$bastionSSH->setCredentials($sshSysLogin, $sshSysPassword);
														}

														$tunnelIsConnected = $bastionSSH->connect();

														if(!$tunnelIsConnected) {
															$this->_SHELL->error("Impossible de se connecter en SSH au bastion du site '".$site."' (".$sshBastionHost.":".$sshBastionPort.")", 'orange');
															$bastionSSH->disconnect();
															return false;
														}

														$sshIp = '127.0.0.1';
														$sshPort = $sshPortForwarding;
														$sshOptions = array(
															'LogLevel=ERROR',
															'StrictHostKeyChecking=no',
															'UserKnownHostsFile=/dev/null'
														);

														$this->_SHELL->print('SSH tunnel is established!', 'green');
													}
													else {
														$this->_SHELL->error("Identifiant (et mot de passe) système pour le SSH manquants", 'orange');
														return false;
													}
												}

												list($sshNetLogin, $sshNetPassword) = $this->_getCredentials($siteConfig, 'scp');

												if($sshNetLogin !== false)
												{
													$remoteSSH = new Network\Ssh($sshIp, $sshPort, null, null, null, false);
													$remoteSSH->setOptions($sshOptions);

													if($sshNetPassword === false) {
														$remoteSSH->useSshAgent($sshNetLogin);
													}
													else {
														$remoteSSH->setCredentials($sshNetLogin, $sshNetPassword);
													}

													$sessionIsConnected = $remoteSSH->connect();

													if($sessionIsConnected)
													{
														$this->_SHELL->print('SSH session is established!', 'green');

														/**
														  * Supprime ^M (\r)
														  */
														switch($siteConfig->os)
														{
															case 'juniper-junos': {
																$fileContents = file_get_contents($exportFile);
																$fileContents = str_replace("\r", '', $fileContents);
																file_put_contents($exportFile, $fileContents, LOCK_EX);
																break;
															}
														}
														
														$scpRemoteFile = $siteConfig->scp_remoteFile;

														$isAliveID = 0;

														$waitingCallback = function(C\Process $scpProcess) use (&$isAliveID) {
															$message = $this->_SHELL->format('Please wait for SCP transfer! (ID: '.$isAliveID++.') (PID: '.$scpProcess->pid.')', 'blue');
															$this->_SHELL->terminal->updateMessage($message);
														};

														$this->_SHELL->EOL();

														try {
															$status = $remoteSSH->putFile($exportFile, $scpRemoteFile, false, 0644, $waitingCallback, 2);
														}
														catch(E\Message $e) {
															$this->_SHELL->error($e->getMessage(), 'orange');
															$status = false;
														}
														catch(\Exception $e) {
															$this->_SHELL->error("SCP ERROR: ".$e->getMessage(), 'red');
															$status = false;
														}

														if($status) {
															$this->_SHELL->print("Copie configuration '".$scpRemoteFile."' terminée!", 'green');
														}
														else {
															$this->_SHELL->error("Impossible d'envoyer en SSH le fichier '".$exportFile."' au site '".$site."' (".$scpRemoteFile.")", 'orange');
														}
													}
													else {
														$this->_SHELL->error("Impossible de se connecter en SSH au site '".$site."' (".$sshIp.":".$sshPort.")", 'orange');
														$status = false;
													}

													$remoteSSH->disconnect();
												}
												else {
													$this->_SHELL->error("Identifiant (et mot de passe) réseau pour le SSH manquants", 'orange');
													$status = false;
												}

												if(isset($bastionSSH)) {
													$bastionSSH->disconnect();
												}

												return $status;
											}
											else {
												$this->_SHELL->error("IP et port SSH absents pour ce site '".$site."'", 'orange');
											}
										}
										else {
											$this->_SHELL->error("SCP est désactivé pour ce site '".$site."'", 'orange');
										}

										break;
									}
									default: {
										$this->_SHELL->error("La méthode '".$method."' n'est pas supportée", 'orange');
									}
								}
							}
							else {
								$this->_SHELL->error("Le configuration du site '".$site."' n'existe pas", 'orange');
							}
						}
						else {
							$this->_SHELL->error("La méthode '".$method."' n'est pas supportée", 'orange');
						}
					}
					else {
						$this->_SHELL->error("La configuration correspondante au site '".$site."' n'a pas été trouvée", 'orange');
					}
				}
				else {
					$this->_SHELL->error("Une erreur s'est produite durant l'export de la configuration", 'orange');
				}
			}
			else {
				$this->_SHELL->error("Le site '".$site."' n'est pas activé", 'orange');
			}

			return false;
		}

		protected function _export(array $firewalls, $type, $format, $force)
		{
			$Core_Template_Abstract = $this->_getExportClass($format);

			if($Core_Template_Abstract !== false)
			{
				$sections = $this->_getExportSections($Core_Template_Abstract, $type);

				if($sections !== false)
				{
					$fwlCounter = count($firewalls);						

					if($fwlCounter > 0)
					{
						if($this->_ORCHESTRATOR->isSaving || !$this->_ORCHESTRATOR->hasChanges || $force)
						{
							try {
								return $this->_templating($Core_Template_Abstract, $firewalls, $sections);
							}
							catch(\Exception $e) {
								$this->_SHELL->throw($e);
								return false;
							}
						}
						else {
							$this->_SHELL->error("Il est vivement recommandé de sauvegarder la configuration avant de l'exporter. Pour l'exporter malgrés tout utilisez l'argument 'force'", 'orange');
						}
					}
					else {
						$this->_SHELL->error("Aucun site n'a été déclaré, il n'y a donc pas de configuration à exporter", 'orange');
					}
				}
				else {
					$this->_SHELL->error("Section type '".$type."' non supporté", 'orange');
				}
			}
			else {
				$this->_SHELL->error("Format d'export '".$format."' non supporté", 'orange');
			}

			return false;
		}

		protected function _getExportClass($format)
		{
			if(array_key_exists($format, self::EXPORT_FORMAT_CLASS)) {
				return self::EXPORT_FORMAT_CLASS[$format];
			}
			else {
				return false;
			}
		}

		protected function _getExportSections($Core_Template_Abstract, $type)
		{
			if($type === null) {
				return $Core_Template_Abstract::OBJECT_TYPE_SECTION;
			}
			elseif(array_key_exists($type, $Core_Template_Abstract::OBJECT_TYPE_SECTION)) {
				return (array) $Core_Template_Abstract::OBJECT_TYPE_SECTION[$type];
			}
			else {
				return false;
			}
		}

		protected function _templating($Core_Template_Abstract, array $firewalls, $sections)
		{
			$exports = array();
			$sites = $this->_objects[Core\Api_Site::OBJECT_KEY];

			$index = 0;
			$fwlCounter = count($firewalls);

			foreach($firewalls as $site => $Firewall)
			{
				$this->_SHELL->print("Préparation de la configuration pour '".$Firewall->name."'", 'green');

				// /!\ On doit passer un template clean pour éviter toutes interactions négatives
				$Core_Template_Abstract = new $Core_Template_Abstract($this->_SHELL, $sites);

				try {
					$status = $Core_Template_Abstract->templating($Firewall, $sections);
				}
				catch(\Exception $e) {
					$this->_SHELL->throw($e);
					$status = false;
				}

				if($status)
				{
					$exports[$site] = $Core_Template_Abstract->export;
					$this->_SHELL->print("Configuration disponible: '".$exports[$site]."'", 'green');

					if($index < $fwlCounter-1) {
						$this->_SHELL->EOL();
						$index++;
					}
				}
				else {
					$msg = "Une erreur s'est produite durant la génération du template '".$Core_Template_Abstract->template."'";
					$msg .= " pour le firewall '".$Firewall->name."'";
					throw new E\Message($msg, E_USER_ERROR);
				}
			}

			return $exports;
		}

		protected function _getCredentials(C\MyArrayObject $siteConfig, $prefix = null, $suffix = null)
		{
			if(C\Tools::is('string&&!empty', $prefix)) {
				$prefix = $prefix.'_';
			}

			if(C\Tools::is('string&&!empty', $suffix)) {
				$suffix = '_'.$suffix;
			}

			return C\Tools::getCredentials($siteConfig, $prefix, $suffix, false, false);
		}
	}