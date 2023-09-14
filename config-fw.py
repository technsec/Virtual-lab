import time
import shlex
import subprocess
import os
import logging
import urllib.request
import socket
from socket import gethostname, gethostbyname
import sys
import ssl
import xml.etree.ElementTree as et
import threading
import requests

LOG_FILENAME = 'azure.log'
logging.basicConfig(filename=LOG_FILENAME,level=logging.INFO, filemode='w',format='[%(levelname)s] (%(threadName)-10s) %(message)s',)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

#We know that the FW Mgmt private IP will be statically set to x.x.0.4
MgmtIp = "10.100.0.4"
#We know that DB IP is going to have x.x.4.5...so just need prefix
DBServerIP = "10.100.4.5"
#NAT FQDN
nat_fqdn= "DatabaseServer"
#The api key is pre-generated for  paloalto/Pal0Alt0@123
api_key = "LUFRPT1CU0dMRHIrOWFET0JUNzNaTmRoYmkwdjBkWWM9alUvUjBFTTNEQm93Vmx0OVhFRlNkOXdJNmVwYWk5Zmw4bEs3NjgwMkh5QT0="

#Need this to by pass invalid certificate issue. Should try to fix this
gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)

#baseStorageAccountName = ""
config_file_url = "https://raw.githubusercontent.com/technsec/Virtual-lab/main/"
config_file_name = "azure-sample.xml"
config_file= "https://raw.githubusercontent.com/technsec/Virtual-lab/main/azure-sample.xml"
config_guess_sql_root_password= "https://raw.githubusercontent.com/technsec/Virtual-lab/main/guess-sql-root-password.cgi"
config_ssh_to_db= "https://raw.githubusercontent.com/technsec/Virtual-lab/main/ssh-to-db.cgi"
config_sql_attack= "https://raw.githubusercontent.com/technsec/Virtual-lab/main/sql-attack.html"
curl_string = 'curl --form file=@%s --insecure "https://%s/api/?type=import&category=configuration&file-name=%s&key=%s"' % (config_file, MgmtIp, config_file, api_key)


def main():
    global config_file_url
    #baseStorageAccountName = sys.argv[2]
    #config_file_url = "https://raw.githubusercontent.com/technsec/Virtual-lab/main/"
    t1 = threading.Thread(name='config_fw',target=config_fw)
    t1.start()
    t2 = threading.Thread(name='config_wp', target=config_wp)
    t2.start()

#Configure Firewall
def load_and_commit_config():
    global api_key
    global MgmtIp
    global config_file
    api_url = "https://10.100.0.4/api"
    headers = {
        "Content-Type": "application/xml",
        "X-PAN-KEY": api_key
    }

    # Read the config file
    #with open(config_file_path, "r") as file:
    file = urllib.request.urlopen(config_file) 
    config_content = file.read()

    # Send the request to load the configuration
    load_url = "https://10.100.0.4/api/running-config"
    response = requests.put(load_url, headers=headers, data=config_content, verify=False)

    if response.status_code == 200:
        print("Configuration loaded successfully.")
    else:
        print(f"Error loading configuration: {response.status_code} - {response.text}")
        return

    # Send the request to commit the configuration
    commit_url = "https://10.100.0.4/api/commit"
    response = requests.post(commit_url, headers=headers, verify=False)

    if response.status_code == 200:
        print("Configuration committed successfully.")
    else:
        print(f"Error committing configuration: {response.status_code} - {response.text}")

#Configure WP server
def config_wp():
    global DBServerIP
    global MgmtIp
    global config_file_url
    global nat_fqdn

    #This means firewall already configured..so exit script.
    if os.path.exists("./wp_configured") == True:
        logger.info("[INFO]: WP already configured. Bon Appetit!")
        return 'true'

    logger.info("[INFO]: Install and Config wordpress server")
    
    #configure the wordpress server
    try:
        subprocess.check_output(shlex.split("sudo apt-get update"))
    except subprocess.CalledProcessError, e:
        logger.info("[ERROR]: apt-get update error")
        return 'false'

    try:
        subprocess.check_output(shlex.split("sudo apt-get install -y apache2"))
    except subprocess.CalledProcessError, e:
        logger.info("[ERROR]: apt-get install apache2 error")
        return 'false'

    try:
        subprocess.check_output(shlex.split("sudo apt-get install -y wordpress"))
    except subprocess.CalledProcessError, e:
        logger.info("[ERROR]: apt-get install wordpress error")
        return 'false'

    try:
        subprocess.check_output(shlex.split("sudo ln -sf /usr/share/wordpress /var/www/html/wordpress"))
    except subprocess.CalledProcessError, e:
        logger.info("[ERROR]: ln -sf wordpress error")
        return 'false'

    try:
        subprocess.check_output(shlex.split("sudo gzip -d /usr/share/doc/wordpress/examples/setup-mysql.gz"))
    except subprocess.CalledProcessError, e:
        logger.info("[ERROR]: gzip error")
        return 'false'

   
    #Then continue to finish wordpress setup
    #Just need a config file
    try:
        subprocess.check_output(shlex.split("sudo bash /usr/share/doc/wordpress/examples/setup-mysql -n Demo -t %s %s" % (DBServerIP, DBServerIP)))
    except subprocess.CalledProcessError, e:
        logger.info("[ERROR]: setup-WP error {}".format(e))
        return 'false'

    #Add user name and password to config file. Need to do this as setup-mysql is interactive!
    try:
        subprocess.check_output(shlex.split("sed -i \"s/define('DB_USER'.*/define('DB_USER', 'demouser');/g\" /etc/wordpress/config-%s.php" % (DBServerIP)))
    except subprocess.CalledProcessError, e:
        logger.info("[ERROR]: setup-WP add user error {}".format(e))
        return 'false'
    try:
        subprocess.check_output(shlex.split("sed -i \"s/define('DB_PASSWORD'.*/define('DB_PASSWORD', 'paloalto@123');/g\" /etc/wordpress/config-%s.php" % (DBServerIP)))
    except subprocess.CalledProcessError, e:
        logger.info("[ERROR]: setup-WP add user password error {}".format(e))
        return 'false'


    #Rename the config file to point to the nat-vm DNS name. This will survive reboots.
    logger.info("[INFO]: NAT FQDN = %s" % nat_fqdn)
    try:
        subprocess.check_output(shlex.split("sudo mv /etc/wordpress/config-%s.php /etc/wordpress/config-%s.php" % (DBServerIP, nat_fqdn)))
    except subprocess.CalledProcessError, e:
        logger.info("[ERROR]: File mv error {}".format(e))
        return 'false'

    #Download guess-password file
    try:
        subprocess.check_output(shlex.split("wget -O /usr/lib/cgi-bin/guess-sql-root-password.cgi %sguess-sql-root-password.cgi"%(config_guess_sql_root_password)))
    except subprocess.CalledProcessError, e:
        logger.info("[ERROR]: wget guess-sql-root-password.cgi error {}".format(e))
        return 'false'

    #Make it executable
    try:
        subprocess.check_output(shlex.split("chmod +x /usr/lib/cgi-bin/guess-sql-root-password.cgi"))
    except subprocess.CalledProcessError, e:
        logger.info("[ERROR]: chmod guess-sql-root-password.cgi error {}".format(e))
        return 'false'

    #Change DB IP address in the guess-sql-root-password cgi script
    try:
        subprocess.check_output(shlex.split("sed -i \"s/DB-IP-ADDRESS/%s/g\" /usr/lib/cgi-bin/guess-sql-root-password.cgi" % (DBServerIP)))
    except subprocess.CalledProcessError, e:
        logger.info("[ERROR]: change DB IP address guess-sql-root-password.cgi error {}".format(e))
        return 'false'


    #Download ssh-to-db.cgi file
    try:
        subprocess.check_output(shlex.split("wget -O /usr/lib/cgi-bin/ssh-to-db.cgi %sssh-to-db.cgi"%(config_ssh_to_db)))
    except subprocess.CalledProcessError, e:
        logger.info("[ERROR]: wget ssh-to-db.cgi  {}".format(e))
        return 'false'

    #Make it executable
    try:
        subprocess.check_output(shlex.split("chmod +x /usr/lib/cgi-bin/ssh-to-db.cgi"))
    except subprocess.CalledProcessError, e:
        logger.info("[ERROR]: chmod guess-sql-root-password.cgi error {}".format(e))
        return 'false'

    #Change DB IP address in the ssh-to-db cgi script
    try:
        subprocess.check_output(shlex.split("sed -i \"s/DB-IP-ADDRESS/%s/g\" /usr/lib/cgi-bin/ssh-to-db.cgi" % (DBServerIP)))
    except subprocess.CalledProcessError, e:
        logger.info("[ERROR]: setup-WP add user password error {}".format(e))
        return 'false'

    #Download sql-attack.html page
    try:
        subprocess.check_output(shlex.split("wget -O /var/www/html/sql-attack.html %ssql-attack.html"%(config_sql_attack)))
    except subprocess.CalledProcessError, e:
        logger.info("[ERROR]: wget sql-attack.html error {}".format(e))
        return 'false'

    #Enable the cgi module
    try:
        subprocess.check_output(shlex.split("ln -sf /etc/apache2/conf-available/serve-cgi-bin.conf /etc/apache2/conf-enabled/serve-cgi-bin.conf"))
    except subprocess.CalledProcessError, e:
        logger.info("[ERROR]: link serve-cgi-bin.conf error {}".format(e))
        return 'false'

    try:
        subprocess.check_output(shlex.split("ln -sf /etc/apache2/mods-available/cgi.load /etc/apache2/mods-enabled/cgi.load"))
    except subprocess.CalledProcessError, e:
        logger.info("[ERROR]: link cgi mods enable error {}".format(e))
        return 'false'

    #Restart apache2 to let this take effect
    try:
        subprocess.check_output(shlex.split("systemctl restart apache2"))
    except subprocess.CalledProcessError, e:
        logger.info("[ERROR]: Apache2 restart error {}".format(e))
        return 'false'

    logger.info("[INFO]: ALL DONE!")
    #Create a marker file that shows WP is already configured so we don't run this script again.
    open("./wp_configured", "w").close()
    return 'true'

if __name__ == "__main__":
    main()

