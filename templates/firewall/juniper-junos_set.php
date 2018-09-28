<?php
/**
  * /!\ La balise de fermeture de PHP '?>' supprime le saut de ligne qui la suit immédiatement
  * Un double saut de ligne est le workaround le plus simple à mettre en place
  */

	foreach($this->_applications as $protocol)
	{
?>

set applications application <?php echo $protocol['name']; ?> protocol <?php echo $protocol['protocol']; ?>
<?php
		if(array_key_exists('options', $protocol))
		{
?>

set applications application <?php echo $protocol['name']; ?> destination-port <?php echo $protocol['options']; ?>
<?php
		}
	}

	foreach($this->_addressBook as $zone => $addresses)
	{
		foreach($addresses as $items)
		{
			// IPv4 & IPv6
			foreach($items as $address)
			{
?>

set security zones security-zone <?php echo $zone; ?> address-book address <?php echo $address['name'].' '.$address['address']; ?>
<?php
			}
		}
	}
?>

<?php
	foreach($this->_accessLists as $accessList)
	{
?>

set security policies from-zone <?php echo $accessList['srcZone']; ?> to-zone <?php echo $accessList['dstZone']; ?> policy <?php echo $accessList['aclName']; ?> description <?php echo '"'.$accessList['description'].'"'; ?>
<?php
		foreach($accessList['srcAdds'] as $srcAdd)
		{
?>

set security policies from-zone <?php echo $accessList['srcZone']; ?> to-zone <?php echo $accessList['dstZone']; ?> policy <?php echo $accessList['aclName']; ?> match source-address <?php echo $srcAdd; ?>
<?php
		}

		foreach($accessList['dstAdds'] as $dstAdd)
		{
?>

set security policies from-zone <?php echo $accessList['srcZone']; ?> to-zone <?php echo $accessList['dstZone']; ?> policy <?php echo $accessList['aclName']; ?> match destination-address <?php echo $dstAdd; ?>
<?php
		}

		foreach($accessList['protoApps'] as $protoApp)
		{
?>

set security policies from-zone <?php echo $accessList['srcZone']; ?> to-zone <?php echo $accessList['dstZone']; ?> policy <?php echo $accessList['aclName']; ?> match application <?php echo $protoApp; ?>
<?php
		}

		if($accessList['action'] === true)
		{
?>

set security policies from-zone <?php echo $accessList['srcZone']; ?> to-zone <?php echo $accessList['dstZone']; ?> policy <?php echo $accessList['aclName']; ?> then permit
<?php
		}
?>

set security policies from-zone <?php echo $accessList['srcZone']; ?> to-zone <?php echo $accessList['dstZone']; ?> policy <?php echo $accessList['aclName']; ?> then log session-init
set security policies from-zone <?php echo $accessList['srcZone']; ?> to-zone <?php echo $accessList['dstZone']; ?> policy <?php echo $accessList['aclName']; ?> then log session-close
set security policies from-zone <?php echo $accessList['srcZone']; ?> to-zone <?php echo $accessList['dstZone']; ?> policy <?php echo $accessList['aclName']; ?> then count
<?php
	}
?>