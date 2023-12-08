#!/bin/zsh

# ./configure_tools.sh

# check if the command returns the SSLError
test(){
    source $shell
    while read -r line; do
        # echo $line
        if [[ $line == *"SSL"* ]]; then
            ssl_error_exists=true
        fi
    done < <($1 2>&1)
    if [ "$ssl_error_exists" = true ] ; then
        return 0
    else
        return 1
    fi
}



export_env_var(){
    # if environment variable is not defined to ns bundle
    if [[ "$(printenv | grep $1)" != *${bundle//\\/$''}* ]]; then
    # need to backup the shell startup script before editing
    backup
    # export variable to startup script
    echo export $1="${bundle}" >> $shell
    # export to the current window
    export $1="${bundle}"
    fi
}

backup(){
    if [ "$have_backup" = false ] ; then
    backup_file="$shell-$(date +%s)"
    echo "Backing up $shell to $backup_file"
    cp $shell $backup_file
    have_backup=true
    fi
}


configure_python(){
    export_env_var REQUESTS_CA_BUNDLE
}

configure_openssl(){
    export_env_var SSL_CERT_FILE
}

configure_curl(){
    export_env_var CURL_CA_BUNDLE
}

configure_node_js(){
    export_env_var NODE_EXTRA_CA_CERTS
}

configure_git(){
    export_env_var GIT_SSL_CAPATH
}

configure_az(){
    # python-based
    if ! tool_exists python
    then
    export_env_var REQUESTS_CA_BUNDLE
    fi
}

# AWS CLI
configure_aws(){
    # aws configure set default.ca_bundle $bundle
    export_env_var AWS_CA_BUNDLE
}

configure_gcloud(){
    bash -c "gcloud config set core/custom_ca_certs_file $bundle"
}

configure_java(){
    # Add cert to java keystore
    bash -c "
    /Library/Internet\ Plug-Ins/JavaAppletPlugin.plugin/Contents/Home/bin/keytool \
    -import -alias netskope-cert-bundle \
    -storepass changeit \
    -file $bundle -noprompt
    "
}

configure_composer(){
    bash -c "composer config --global cafile $bundle"
}

# aws_cdk
configure_npm(){
    bash -c "npm config set cafile $bundle"
}

configure_android_studio_app(){
    # Add cert to Android keystore for Android Studio
    bash -c "
    /Applications/Android\ Studio.app/Contents/jre/Contents/Home/bin/keytool \
    -import -alias netskope-cert-bundle -keystore \
    /Applications/Android\ Studio.app/Contents/jre/Contents/Home/lib/security/cacerts -storepass changeit \
    -file $bundle -noprompt
    "
}


test(){
    while read -r line; do
        # echo $line
        if [[ $line == *"SSL"* ]]; then
        ssl_error_exists=true
        fi
    done < <($1 2>&1)
    if [ "$ssl_error_exists" = true ] ; then
    echo 'FAIL'
    else
        echo 'SUCCESS'
    fi
}

tool_exists(){
    # if it is app
    if [[ ${1:(-4)} == ".app" ]]
    then
        # check for presence under Applications folder
        if [[ "$(ls /Applications)" == *$1* ]]
        then return 0
        fi
        return 1
    fi
    # if command not found
    if ! command -v $1 &> /dev/null
    # alternative:
    # if ! [ -x "$(command -v $1)" ]
    then
        return 1    # false
    fi
    return 0
}




get_shell(){
    my_shell=$(echo $SHELL)
    echo $my_shell
    if [[ $my_shell == *"bash"* ]]
    then
        shell=~/.bash_profile
    else
        shell=~/.zshrc
    fi
}

################################# MAIN ###################################

ns_data_dir="/Library/Application\ Support/Netskope/STAgent/data"
# sudo sh -c "cat '/Library/Application Support/Netskope/STAgent/data/nscacert.pem' '/Library/Application Support/Netskope/STAgent/data/nstenantcert.pem' > '/Library/Application Support/Netskope/STAgent/data/netskope-cert-bundle.pem'"
bundle="$ns_data_dir/netskope-cert-bundle.pem"
# check if using bash or zsh
get_shell
echo "Bundle location : $bundle"
echo "Shell : $shell"
# generate cert bundle
if [ -f "$bundle" ]
    then
        echo "Certificate bundle already exists"
    else
        # generate bundle
        eval cd $ns_data_dir
        cacert="$ns_data_dir"/nscacert.pem
        tenantcert="$ns_data_dir"/nstenantcert.pem
        CA="https://ccadb-public.secure.force.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites"
        sudo sh -c "cat $tenantcert $cacert > $bundle"
        sudo sh -c "curl $CA >> ${bundle}"
    fi

# list of supported tools
declare -a tools=(
    "aws"
    "az"
    "curl"
    "openssl"
    "git"
    "java"
    "python"
    "gcloud"
    "npm"
    "composer"
    "Android Studio.app"
    "Node.JS.app"
    # "Salesforce Apex Dataloader"
)
have_backup=false # no backup created yet
# configure each tool
for tool in "${tools[@]}"
do
    echo "Checking for presence of $tool"
    if tool_exists $tool
    then
        echo "Configuring $tool for Netskope"
        configure_"$(echo $tool | tr ' .' _ | tr '[:upper:]' '[:lower:]')"
    else
        >&2 echo "$tool not detected"
    fi
done
echo "Done"
