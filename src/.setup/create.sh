#!/bin/bash

sql=mysql
host=localhost
user=auth3
database=auth3


echo "Choose a script to run: "
echo

choices=('create' 'drop' 'insert test content' 'exit')
show_hash=false

select choice in "${choices[@]}"; do
	[[ -n $choice ]] || { echo "Invalid choice." >&2; continue; }

	case $choice in
		create)
			script="create.sql"
			;;
		drop)
			script="drop.sql"
			;;
		'insert test content')
			script="testcontent.sql"
			show_hash=true
			;;
		exit)
			echo "Exiting"
			exit 0
	esac

	echo
	echo -n "MySQL Password:"
			read -s password
	echo

	$sql \
		--host=$host\
		--user=$user\
		--password=$password\
		--database=$database\
		--execute="SOURCE $script"
	if $show_hash; then
		echo
		echo "hashed password \"test\""
		echo `php -r 'echo password_hash("test", PASSWORD_DEFAULT), PHP_EOL;'`;
	fi

	exit 0
	
	break
done
