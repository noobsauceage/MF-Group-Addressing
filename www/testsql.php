<?php
$con = mysql_connect("localhost","root","goobypls");
if (!$con)
  {
  die('Could not connect: ' . mysql_error());
  }

mysql_select_db("test", $con);

$sql="INSERT INTO test2 (Name, Value)
VALUES
('$_POST[name]','$_POST[value]')";

if (!mysql_query($sql,$con))
  {
  die('Error: ' . mysql_error());
  }
echo "1 record added";

mysql_close($con);
?> 
