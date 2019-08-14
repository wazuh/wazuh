WAZUH
Copyright (C) 2015-2019, Wazuh Inc.

Based on OSSEC HIDS 0.8
Copyright (c) 2004-2006 Daniel B. Cid  	<daniel.cid@gmail.com>
		                        <dcid@ossec.net>


= Informacje o OSSEC HIDS =

Zobacz https://www.wazuh.com


= Zalecana instalacja =

Instalacja OSSEC HIDS jest bardzo prosta. Może być przeprowadzona
w szybki sposób (przy użyciu skryptu install.sh z domyślnymi
wartościami) lub dostosowana do użytkownika (ręcznie lub poprzez
zmianę domyślnych wartości w skrypcie install.sh). POLECAM KAŻDEMU
używanie SZYBKIEGO SPOSOBU! Tylko developerzy i zaawansowani
użytkownicy powinni używać innych metod.

Kroki szybkiego sposobu:

1- Uruchom skrypt ./install.sh. Poprowadzi Cie on przez proces
   instalacji.

2- Skrypt zainstaluje wszystko do katalogu /var/ossec oraz
   spróbuje stworzyć w systemie skrypt inicjujący (w katalogu
   /etc/rc.local lub /etc/rc.d/init.d/ossec). Jeśli skrypt nie
   zostanie utworzony, można postępując zgodnie z instrukcjami
   z install.sh spowodować uruchamianie OSSEC HIDS podczas
   startu systemu. Aby wystartować ręcznie wystarczy uruchomić
   /var/ossec/bin/ossec-control start

3- Jeśli zamierzasz używać kilku klientów, powinieneś najpierw
   zainstalowac serwer. Do stworzenia odpowiednich kluczy użyj
   narzędzia manage_agents.

4- Miłego użytkowania.


= Instalacja i uruchmienie (99,99% powinieneś przeczytać POWYŻEJ) =


Kroki ręcznej instalacji:

1- Utwórz potrzebne katalogi (domyślnie /var/ossec).
2- Przenieś odpowiednie pliki do katalogu ossec.
3- Skompiluj wszystko.
4- Przenieś binaria do katalodu domyślnego.
5- Dodaj odpowiednich użytkowników.
6- Ustaw odpowiednie prawa dla plików.


Powyższe 5 (bez 5) kroków jest wykonywane w Makefile (zobasz make server).

Makefile czyta opcje z pliku LOCATION. Możesz w nim zmienić
wszystko co potrzebujesz.

Aby skompilować wszystko samemu:

	% make clean
	% make all (step 3)
	% su
	# make server (odpowiada za kroki 1,2,4 oraz 6)

*Przed uruchomieniem make server, upewnij się, że masz utworzonych
odpowiednich użytkowników. Makefile nie utworzy ich.
