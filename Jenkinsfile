#!/usr/bin/env groovy
/** 
	* Groovy Jenkinsfile to test Wazuh modules
	* from https://github.com/okynos/wazuh.git
	* by José Fernandez Aguilera

*/

try{
node{
	stage 'Cloning code'
	def workspace = pwd()	
	echo "workspace=${workspace}"
	
	sh 'git clone https://github.com/okynos/wazuh.git'	

	stage 'testing...'
	echo "everything cloned :)"

}
}
catch(exc){

}
