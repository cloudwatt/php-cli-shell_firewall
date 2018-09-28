<?php
/**
  * /!\ La balise de fermeture de PHP '?>' supprime le saut de ligne qui la suit immédiatement
  * Un double saut de ligne est le workaround le plus simple à mettre en place
  */
?>
applications
{
<?php
	foreach($this->_applications as $protocol)
	{
?>
	application <?php echo $protocol['name']; ?>

	{
		protocol <?php echo $protocol['protocol']; ?>;
<?php
		if(array_key_exists('options', $protocol))
		{
?>
		destination-port <?php echo $protocol['options']; ?>;
<?php
		}
?>
	}
<?php
	}
?>
}
security
{
	zones
	{
<?php
	foreach($this->_addressBook as $zone => $addresses)
	{
?>
		security-zone <?php echo $zone; ?>

		{
			address-book
			{
<?php
		foreach($addresses as $items)
		{
			// IPv4 & IPv6
			foreach($items as $address)
			{
?>
				address <?php echo $address['name'].' '.$address['address']; ?>;
<?php
			}
		}
?>
			}
		}
<?php
	}
?>
	}
	policies
	{
<?php
	foreach($this->_accessLists as $accessList)
	{
?>
		from-zone <?php echo $accessList['srcZone']; ?> to-zone <?php echo $accessList['dstZone']; ?>

		{
			policy <?php echo $accessList['aclName']; ?>

			{
				description "<?php echo $accessList['description']; ?>";
				match {
					source-address [ <?php echo implode(' ', $accessList['srcAdds']); ?> ];
					destination-address [ <?php echo implode(' ', $accessList['dstAdds']); ?> ];
					application [ <?php echo implode(' ', $accessList['protoApps']); ?> ];
				}
				then {
					<?php echo ($accessList['action']) ? ('permit;') : (''); ?>

					log {               
						session-init;
						session-close;
					}
					count;
				}
			}
		}
<?php
	}
?>
	}
}