def labels = ['centos-7-slave']


//Stage standard ossec compilations
def  standard_compilations(label){
    dir ('src') {
        if(  label != 'centos-5-slave'){
            sh 'sudo make --warn-undefined-variables V=1 TARGET=agent install'
            sh 'sudo make clean && sudo rm -rf /var/ossec/'
            sh 'sudo make --warn-undefined-variables V=1 TARGET=server install'
            sh 'sudo make clean'
        } else{
            sh 'sudo make --warn-undefined-variables USE_LEGACY_SSL=yes V=1 TARGET=agent install'
            sh 'sudo make clean && sudo rm -rf /var/ossec/'
            sh 'sudo make --warn-undefined-variables USE_LEGACY_SSL=yes V=1 TARGET=server install'
            sh 'sudo make clean'
        }
    }
}


for (label in labels) {

    stage (label){

        node(label) {
            stage ('Standard Compilations'){
                standard_compilations(label)
            }
        }
    }
}
