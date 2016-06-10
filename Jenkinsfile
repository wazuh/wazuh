/**
 * Jenkinsfile for OSSEC Wazuh
 * Copyright (C) 2016 Wazuh Inc.
 * June 22, 2016.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

node {
    
    //Stage checkout source
    stage name: 'Checkout source', concurrency: 1
    
    checkout scm
    sh 'sudo apt-get update'
    
    //Stage unit tests
    stage name: 'Unit tests', concurrency: 1
    
    dir ('src') { 
        sh 'sudo make --warn-undefined-variables test_valgrind'
        sh 'sudo make clean'
    }
    
    //Stage code scanners
    stage name: 'Code scanners', concurrency: 1
    
    dir ('src') {
        
    }
    
    //Stage standard ossec compilations
    stage name: 'Standard OSSEC compilations', concurrency: 1 
    
    dir ('src') {
        sh 'sudo make --warn-undefined-variables V=1 TARGET=agent install'
        sh 'sudo make clean && sudo rm -rf /var/ossec/'
        sh 'sudo make --warn-undefined-variables V=1 TARGET=server install'
        sh 'sudo make clean'
    }  
    
    //Stage rule tests
    stage name: 'Rule tests', concurrency: 1 
    
    dir ('src') {
        sh 'sudo cat /var/ossec/etc/ossec.conf'
        sh 'sudo make V=1 TARGET=server test-rules'
    }
    
    //Stage advanced ossec compilation
    stage name: 'Advanced OSSEC compilations', concurrency: 1 
    
    dir ('src') {
        sh 'sudo make --warn-undefined-variables V=1 TARGET=local install'
        sh 'sudo make clean && sudo rm -rf /var/ossec/'
        sh 'sudo make --warn-undefined-variables V=1 TARGET=hybrid install'
        sh 'sudo make clean && sudo rm -rf /var/ossec/'
    
        def matrixOptionsX = ['DATABASE=none', 'DATABASE=pgsql', 'DATABASE=mysql']
        def matrixOptionsY = ['USE_GEOIP=1', '']    
        
        sh 'sudo apt-get -y install geoip-bin geoip-database libgeoip-dev libgeoip1 libpq-dev libpq5 libmysqlclient-dev'        
        
        for (optionX in matrixOptionsX){
            for (optionY in matrixOptionsY) {
                sh 'sudo make --warn-undefined-variables V=1 TARGET=server '+optionX+' '+optionY+' install'
                sh 'sudo make clean && sudo rm -rf /var/ossec/'
            }
        }
    }
    
    //Stage windows compilation
    stage name: 'Windows compilation', concurrency: 1
    
    dir ('src') {
        sh 'sudo apt-get -y install aptitude && sudo aptitude -y install mingw-w64 nsis'
        sh 'sudo make --warn-undefined-variables TARGET=winagent'
        sh 'sudo make clean && sudo rm -rf /var/ossec/'
    }
    
}
