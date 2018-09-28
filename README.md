# PHP-CLI SHELL for FIREWALL

This repository is the addon for PHP-CLI SHELL about FIREWALL (acl) service.  
With this addon you can create ACLs (monosite, failover and fullmesh) and generate template for your firewall appliance.  
For the moment, only JunOS templates are availables. There are 2 templates for JunOS: one formated with {} and one with set commands.    

ACL monosite: basic ACL, source(s), destination(s), no automation. For this ACL category you can not enable fullmesh option! 
ACL failover: failover ACL(s) will be automaticaly generated for all failover sites in inbound or outbound.  
ACL failover with fullmesh option: source and destination of ACL will be isolated to process automation.

You have to use base PHP-CLI SHELL project that is here: https://github.com/cloudwatt/php-cli-shell_base


# INSTALLATION

#### APT PHP
__*https://launchpad.net/~ondrej/+archive/ubuntu/php*__
* add-apt-repository ppa:ondrej/php
* apt-get update
* apt install php7.1-cli php7.1-mbstring php7.1-readline

#### REPOSITORIES
* git clone https://github.com/cloudwatt/php-cli-shell_base
* git checkout tags/v1.1
* git clone https://github.com/cloudwatt/php-cli-shell_firewall
* git checkout tags/v1.0
* Merge these two repositories

#### PHPIPAM (Optionnal)
If you have PHPIPAM and you want object name autocompletion, you have to perform these steps:
* git clone https://github.com/cloudwatt/php-cli-shell_phpipam
* git checkout tags/v1.1
* Merge this repository with two previous repositories (base and firewall)
* Install PHP-CLI SHELL for PHPIPAM with README helper  
  https://github.com/cloudwatt/php-cli-shell_phpipam/blob/master/README.md
	
#### CONFIGURATION FILE
* mv configurations/firewall.json.example configurations/firewall.json
* vim configurations/firewall.json
    * Adapt configuration to your network topology
	* Of course you can add more than two sites
	* Do not change topology attribute names: internet, onPremise, interSite, private
	* /!\ Zone name between site (MPLS-ADM, MPLS-USR) must be the same on all sites  
	  *This is will change in next release to add more flexibility*
* Optionnal
    * You can create user configuration files for base and firewall services to overwrite some configurations  
	  These files will be ignored for commits, so your user config files can not be overwrited by a futur release
	* vim configurations/firewall.user.json
	  Change configuration like path or file
	* All *.user.json files are ignored by .gitignore
	

#### PHP LAUNCHER FILE
* mv firewall.php.example firewall.php
* vim firewall.php
    * Change [IPAM_SERVER_KEY] with the key of your PHPIPAM server in configuration file  
	  You can add many PHPIPAM server, it is compatible multiple PHPIPAM  
	  If you have not PHPIPAM service, remove argument or keep it empty

#### CREDENTIALS FILE (Only if you install PHPIPAM service)
/!\ For security reason, use a read only account!  
__*Change informations which are between []*__
* vim credentialsFile
    * read -sr USER_PASSWORD_INPUT
    * export IPAM_[IPAM_SERVER_KEY]_LOGIN=[YourLoginHere]
    * export IPAM_[IPAM_SERVER_KEY]_PASSWORD=$USER_PASSWORD_INPUT  
	__Change [IPAM_SERVER_KEY] with the key of your PHPIPAM server in configuration file__


# EXECUTION

#### SHELL
Launch PHP-CLI Shell for FIREWALL service
* source credentialsFile
* php firewall.php

#### CLI
Call commands directly from your OS shell.  
__*Informations between [] are optionnal*__
* source credentialsFile
* php firewall.php --site name|all --create_host "name;IPv4[;IPv6]" --create_subnet "name;IPv4/mask[;IPv6/mask]" --create_network "name;IPv4-IPv4[;IPv6-IPv6]"  
  --create_rule monosite|failover [--fullmesh] --action permit|deny  
  --source_host name --source_subnet name --source_network name  
  --destination_host name --destination_subnet name --destination_network name  
  --protocol protocol;number[-number] --description maDescription  
  --save [name;[force]] --export_configuration "junos[;force]"