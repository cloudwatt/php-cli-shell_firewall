# PHP-CLI SHELL for FIREWALL

This repository is the addon for PHP-CLI SHELL about FIREWALL (acl) service.  
With this addon you can create ACLs (monosite, failover and fullmesh) and generate template for your firewall appliance.  
It is possible to upload ACLs config file to firewall with SCP. For SCP, you can use an SSH bastion.    

For the moment, there are 3 templates:
* Juniper JunOS  
  __there are 2 templates for Juniper JunOS: one formated with {} and one with set commands__
* Cisco ASA  
  __there are 2 templates for Cisco ASA: one for the firewall itself and one for VPN DAP (Dynamic Access Policies)__
* Web HTML  

ACL monosite:
* basic ACL, source(s), destination(s), no automation. For this ACL category you can not enable fullmesh option!  

ACL failover:
* __without fullmesh option:__ failover ACL(s) will be automaticaly generated for all failover sites in inbound or outbound.  
* __with fullmesh option:__ like without but source and destination of ACL will be isolated per zone to process automation.

You have to use base PHP-CLI SHELL project that is here: https://github.com/cloudwatt/php-cli-shell_base


# INSTALLATION

#### APT PHP
Ubuntu only, you can get last PHP version from this PPA:  
__*https://launchpad.net/~ondrej/+archive/ubuntu/php*__
* add-apt-repository ppa:ondrej/php
* apt update

You have to install a PHP version >= 7.1:
* apt install php7.3-cli php7.3-mbstring php7.3-readline php7.3-curl  
__Do not forget to install php7.3-curl if you use PHPIPAM__

#### REPOSITORIES
* git clone https://github.com/cloudwatt/php-cli-shell_base
* git checkout tags/v2.1
* git clone https://github.com/cloudwatt/php-cli-shell_firewall
* git checkout tags/v2.1
* Merge these two repositories

#### PHPIPAM (Optionnal)
If you have PHPIPAM and you want object name autocompletion, you have to perform these steps:
* git clone https://github.com/cloudwatt/php-cli-shell_phpipam
* git checkout tags/v2.1
* Merge this repository with two previous repositories (base and firewall)
* Install PHP-CLI SHELL for PHPIPAM with README helper  
  https://github.com/cloudwatt/php-cli-shell_phpipam


#### CONFIGURATION FILE
__[env] is not used by PHP-CLI, it is for user when he has many environments or sites to managed__
* mv applications/firewall/configurations/firewall.envA.json.example configurations/firewall.[env].json
* vim configurations/firewall.[env].json
    * Adapt configuration to your network topology
	* Of course you can add more than two sites
	* Do not change topology attribute names: internet, onPremise, interSite, private
* Optionnal
    * You can create user configuration files for base and firewall services to overwrite some configurations  
	  These files will be ignored for commits, so your user config files can not be overwrited by a futur release
	* mv applications/firewall/configurations/firewall.envA.user.json.example configurations/firewall.[env].user.json
	* vim configurations/firewall.[env].user.json
	  Change configuration like path or file
	* All *.user.json files are ignored by .gitignore
* Cisco-ASA
    * Add this configuration in options section under sites to declare a global zone: "globalZone": "global"  


#### PHP LAUNCHER FILE
* mv firewall.php.example firewall.php
* vim firewall.php
    * Change [IPAM_SERVER_KEY] with the key of your PHPIPAM server in configuration file  
	  You can add many PHPIPAM server, it is compatible multiple PHPIPAM  
	  If you have not PHPIPAM service, remove argument or keep it empty  
__[env] is not used by PHP-CLI, it is for user when he has many environments or sites to managed__
* mv firewall.envA.php.example firewall.[env].php
* vim firewall.[env].php
    * Change [env] with the name of your environment


#### CREDENTIALS FILE
__*Change informations which are between []*__
* vim credentialsFile
    * read -sr USER_PASSWORD_INPUT
	* export SSH_SYS_LOGIN=[YourSystemLoginHere]
	* export SSH_NET_LOGIN=[YourNetworkLoginHere]
	* export SSH_NET_PASSWORD=$USER_PASSWORD_INPUT  
	__Bastion authentication must be base on certificate__  

	__PHPIPAM__ (Only if you use PHPIPAM service/addon)  
	/!\ For security reason, use a read only account!
	* export IPAM_[IPAM_SERVER_KEY]_LOGIN=[YourLoginHere]
    * export IPAM_[IPAM_SERVER_KEY]_PASSWORD=$USER_PASSWORD_INPUT  
	__Change [IPAM_SERVER_KEY] with the key of your PHPIPAM server in configuration file__  


# EXECUTION

#### SHELL
Launch PHP-CLI Shell for FIREWALL service
* source credentialsFile
* php firewall.[env].php

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