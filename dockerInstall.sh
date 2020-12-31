#! /usr/bin/bash

# Utility method to prompt the user for a config variable and export it
prompt_and_export() {
    local varName="$1"
    local promptMsg="$3"
    local answer

    read -p "$promptMsg " answer </dev/tty
    if [ "$answer" ]; then
        export $varName="$answer"
    else
        exit 0
    fi
}

# Utility method to replace all instances of given variables in a file
replace_all() {
    local filename="$1"
    local var

    for var in ${@:2}; do
        sed -i -e "s|$var|${!var}|g" $filename
    done
}

apt update
apt upgrade -y
apt install git curl openssl -y

curl -fsSL https://get.docker.com -o get-docker.sh
bash get-docker.sh

git clone https://github.com/hakwerk/labca
cd labca
version=$(git describe --always HEAD 2>/dev/null)

prompt_and_export LABCA_FQDN "$LABCA_FQDN" "FQDN (Fully Qualified Domain Name) for this PKI host (users will use this in their browsers and clients)?"


[ -e "gui/data/config.json" ] || echo -e "{\n  \"config\": {\n    \"complete\": false\n  },\n  \"labca\": {\n    \"fqdn\": \"$LABCA_FQDN\"\n  },\n  \"version\": \"\"\n}" > "gui/data/config.json"
replace_all gui/data/openssl.cnf LABCA_FQDN
replace_all gui/data/issuer/openssl.cnf LABCA_FQDN
replace_all acme_tiny.py LABCA_FQDN

grep \"version\" gui/data/config.json &>/dev/null || sed -i -e 's/^}$/,\n  "version": ""\n}/' gui/data/config.json
sed -i -e "s/\"version\": \".*\"/\"version\": \"$version\"/" gui/data/config.json


sed -i -e "s|\[LABCA_CPS_LOCATION\]|http://$LABCA_FQDN/cps/|g" www/cps/index.html
sed -i -e "s|\[LABCA_CERTS_LOCATION\]|http://$LABCA_FQDN/certs/|g" www/cps/index.html

cd www
mkdir -R "../gui/data/root-ca" 
mkdir -R "../gui/data/issuer/ca-int"
export PKI_ROOT_CERT_BASE="../gui/data/root-ca"
export PKI_INT_CERT_BASE="../gui/data/issuer/ca-int"

PKI_ROOT_DN=$(openssl x509 -noout -in $PKI_ROOT_CERT_BASE.pem -subject | sed -e "s/subject= //")
sed -i -e "s|\[PKI_ROOT_DN\]|$PKI_ROOT_DN|g" certs/index.html
PKI_ROOT_VALIDITY="$(openssl x509 -noout -in $PKI_ROOT_CERT_BASE.pem -startdate | sed -e "s/.*=/Not Before: /")<br/> $(openssl x509 -noout -in $PKI_ROOT_CERT_BASE.pem -enddate | sed -e "s/.*=/Not After: /")"
sed -i -e "s|\[PKI_ROOT_VALIDITY\]|$PKI_ROOT_VALIDITY|g" certs/index.html
PKI_INT_DN=$(openssl x509 -noout -in $PKI_INT_CERT_BASE.pem -subject | sed -e "s/subject= //")
sed -i -e "s|\[PKI_INT_DN\]|$PKI_INT_DN|g" certs/index.html
PKI_INT_VALIDITY="$(openssl x509 -noout -in $PKI_INT_CERT_BASE.pem -startdate | sed -e "s/.*=/Not Before: /")<br/> $(openssl x509 -noout -in $PKI_INT_CERT_BASE.pem -enddate | sed -e "s/.*=/Not After: /")"
sed -i -e "s|\[PKI_INT_VALIDITY\]|$PKI_INT_VALIDITY|g" certs/index.html

sed -i -e "s|\[PKI_COMPANY_NAME\]|$PKI_DEFAULT_O|g" cps/index.html
sed -i -e "s|\[PKI_ROOT_DN\]|$PKI_ROOT_DN|g" cps/index.html
PKI_ROOT_FINGERPRINT="$(openssl x509 -noout -in $PKI_ROOT_CERT_BASE.pem -fingerprint | sed -e "s/.*=//" | sed -e "s/.\{21\}/&\\\n/g")"
sed -i -e "s|\[PKI_ROOT_FINGERPRINT\]|$PKI_ROOT_FINGERPRINT|g" cps/index.html
sed -i -e "s|\[PKI_ROOT_VALIDITY\]|$PKI_ROOT_VALIDITY|g" cps/index.html

sed -i -e "s|\[PKI_COMPANY_NAME\]|$PKI_DEFAULT_O|g" terms/v1.html
cd ..

mkdir ssl
cd ssl
openssl req -x509 -nodes -sha256 -newkey rsa:2048 -keyout labca_key.pem -out labca_cert.pem -days 7 \
            -subj "/O=LabCA/CN=$LABCA_FQDN" -reqexts SAN -extensions SAN \
            -config <(cat /etc/ssl/openssl.cnf <(printf "\n[SAN]\nbasicConstraints=CA:FALSE\nnsCertType=server\nsubjectAltName=DNS:$LABCA_FQDN"))
cd ..

git clone https://github.com/letsencrypt/boulder
cd boulder
if [ -e "sa/_db-next/migrations/20190221140139_AddAuthz2.sql" ]; then
cp sa/_db-next/migrations/20190221140139_AddAuthz2.sql sa/_db/migrations/
fi
if [ -e "sa/_db-next/migrations/20190524120239_AddAuthz2ExpiresIndex.sql" ]; then
cp sa/_db-next/migrations/20190524120239_AddAuthz2ExpiresIndex.sql sa/_db/migrations/
fi
patch -p1 < ../core_interfaces.patch
patch -p1 < ../policy_pa.patch
patch -p1 < ../ra_ra.patch
patch -p1 < ../mail_mailer.patch
patch -p1 < ../expiration-mailer_main.patch
patch -p1 < ../notify-mailer_main.patch
patch -p1 < ../bad-key-revoker_main.patch

sed -i -e "s|https://letsencrypt.org/docs/rate-limits/|http://$LABCA_FQDN/rate-limits|" errors/errors.go
sed -i -e "s/\"150405/\"060102150405/" log/log.go
mkdir -p "cmd/mail-tester"
cp ../mail-tester.go cmd/mail-tester/main.go
cd ..

[ -d "boulder_labca" ] || mkdir -p "boulder_labca"
cd "boulder_labca"
[ ! -e "secrets/smtp_password" ] || mv "secrets/smtp_password" "secrets/smtp_password_PRESERVE"
cp -r "../boulder/test/*" -T "."
[ ! -e "secrets/smtp_password_PRESERVE" ] || mv "secrets/smtp_password_PRESERVE" "secrets/smtp_password"
patch -p1 -o "entrypoint.sh" < ../entrypoint.patch
patch -p1 -o "startservers.py" < ../startservers.patch 
patch -p1 < ../startservers.patch
patch -p1 -o "config/ca-a.json" < ../test_config_ca_a.patch
patch -p1 -o "config/ca-b.json" < ../test_config_ca_b.patch

patch -p1 -o "config/expiration-mailer.json" < ../config_expiration-mailer.patch
patch -p1 -o "config/notify-mailer.json" < ../config_notify-mailer.patch
patch -p1 -o "config/bad-key-revoker.json" < ../config_bad-key-revoker.patch

sed -i -e "s/test-ca2.pem/test-ca.pem/" config/ocsp-responder.json
sed -i -e "s/test-ca2.pem/test-ca.pem/" config/ocsp-updater.json
sed -i -e "s/test-ca2.pem/test-ca.pem/" config/publisher.json
sed -i -e "s/test-ca2.pem/test-ca.pem/" config/ra.json
sed -i -e "s/test-ca2.pem/test-ca.pem/" config/wfe.json
sed -i -e "s/test-ca2.pem/test-ca.pem/" config/wfe2.json
sed -i -e "s|/tmp/intermediate-cert-rsa-a.pem|labca/test-ca.pem|" config/akamai-purger.json
sed -i -e "s|/tmp/intermediate-cert-rsa-a.pem|labca/test-ca.pem|" config/ocsp-responder.json
sed -i -e "s|/tmp/intermediate-cert-rsa-a.pem|labca/test-ca.pem|" config/ocsp-updater.json
sed -i -e "s|/tmp/intermediate-cert-rsa-a.pem|labca/test-ca.pem|" config/publisher.json
sed -i -e "s|/tmp/intermediate-cert-rsa-a.pem|labca/test-ca.pem|" config/ra.json
sed -i -e "s|/tmp/intermediate-cert-rsa-a.pem|labca/test-ca.pem|" config/wfe.json
sed -i -e "s|/tmp/intermediate-cert-rsa-a.pem|labca/test-ca.pem|" config/wfe2.json
sed -i -e "s/5001/443/g" config/va.json
sed -i -e "s/5002/80/g" config/va.json
sed -i -e "s/5001/443/g" config/va-remote-a.json
sed -i -e "s/5002/80/g" config/va-remote-a.json
sed -i -e "s/5001/443/g" config/va-remote-b.json
sed -i -e "s/5002/80/g" config/va-remote-b.json
sed -i -e "s|http://boulder:4000/terms/v1|http://$LABCA_FQDN/terms/v1|" config/wfe.json
sed -i -e "s|https://boulder:4431/terms/v7|https://$LABCA_FQDN/terms/v1|" config/wfe2.json
sed -i -e "s|http://boulder:4430/acme/issuer-cert|http://$LABCA_FQDN/acme/issuer-cert|" config/ca-a.json
sed -i -e "s|http://boulder:4430/acme/issuer-cert|http://$LABCA_FQDN/acme/issuer-cert|" config/ca-b.json
sed -i -e "s|http://127.0.0.1:4000/acme/issuer-cert|http://$LABCA_FQDN/acme/issuer-cert|" config/ca-a.json
sed -i -e "s|http://127.0.0.1:4000/acme/issuer-cert|http://$LABCA_FQDN/acme/issuer-cert|" config/ca-b.json
sed -i -e "s|http://boulder:4430/acme/issuer-cert|http://$LABCA_FQDN/acme/issuer-cert|" config/wfe2.json
sed -i -e "s|http://127.0.0.1:4000/acme/issuer-cert|https://$LABCA_FQDN/acme/issuer-cert|" config/wfe2.json
sed -i -e "s|http://127.0.0.1:4002/|http://$LABCA_FQDN/ocsp/|g" config/ca-a.json
sed -i -e "s|http://127.0.0.1:4002/|http://$LABCA_FQDN/ocsp/|g" config/ca-b.json
sed -i -e "s|http://example.com/cps|http://$LABCA_FQDN/cps/|g" config/ca-a.json
sed -i -e "s|http://example.com/cps|http://$LABCA_FQDN/cps/|g" config/ca-b.json
sed -i -e "s|1.2.3.4|1.3.6.1.4.1.44947.1.1.1|g" config/ca-a.json
sed -i -e "s|1.2.3.4|1.3.6.1.4.1.44947.1.1.1|g" config/ca-b.json
sed -i -e 's|            "crl_url": "http://example.com/crl",||g' config/ca-a.json
sed -i -e 's|            "crl_url": "http://example.com/crl",||g' config/ca-b.json
sed -i -e "s/Do What Thou Wilt/This PKI is only meant for internal (lab) usage; do NOT use this on the open internet\!/g" config/ca-a.json
sed -i -e "s/Do What Thou Wilt/This PKI is only meant for internal (lab) usage; do NOT use this on the open internet\!/g" config/ca-b.json
sed -i -e "s/ocspURL.Path = encodedReq/ocspURL.Path += encodedReq/" ocsp/helper/helper.go
sed -i -e "s/\"dnsTimeout\": \".*\"/\"dnsTimeout\": \"3s\"/" config/ra.json
sed -i -e "s/\"dnsTimeout\": \".*\"/\"dnsTimeout\": \"3s\"/" config/va.json
sed -i -e "s/\"dnsTimeout\": \".*\"/\"dnsTimeout\": \"3s\"/" config/va-remote-a.json
sed -i -e "s/\"dnsTimeout\": \".*\"/\"dnsTimeout\": \"3s\"/" config/va-remote-b.json

for file in `find . -type f | grep -v .git`; do
    sed -i -e "s|test/|labca/|g" $file
done

sed -i -e "s/names/name\(s\)/" example-expiration-template
rm test-ca2.pem

export PKI_DNS=$(grep dns $adminDir/data/config.json | perl -p0e 's/.*?:\s+(.*)/\1/' | sed -e 's/\",//g' | sed -e 's/\"//g')
export PKI_DOMAIN=$(grep fqdn $adminDir/data/config.json | sed -e 's/.*:[ ]*//' | sed -e 's/\",//g' | sed -e 's/\"//g' | perl -p0e 's/.*?\.//')
export PKI_DOMAIN_MODE=$(grep domain_mode $adminDir/data/config.json | sed -e 's/.*:[ ]*//' | sed -e 's/\",//g' | sed -e 's/\"//g')
export PKI_LOCKDOWN_DOMAINS=$(grep lockdown $adminDir/data/config.json | grep -v domain_mode | sed -e 's/.*:[ ]*//' | sed -e 's/\",//g' | sed -e 's/\"//g')
export PKI_WHITELIST_DOMAINS=$(grep whitelist $adminDir/data/config.json | grep -v domain_mode | sed -e 's/.*:[ ]*//' | sed -e 's/\",//g' | sed -e 's/\"//g')

export PKI_EMAIL_SERVER=$(grep server $adminDir/data/config.json | head -1 | perl -p0e 's/.*?:\s+(.*)/\1/' | sed -e 's/\",//g' | sed -e 's/\"//g')
export PKI_EMAIL_PORT=$(grep port $adminDir/data/config.json | head -1 | perl -p0e 's/.*?:\s+(.*)/\1/' | sed -e 's/\",//g' | sed -e 's/\"//g')
export PKI_EMAIL_USER=$(grep user $adminDir/data/config.json | head -1 | perl -p0e 's/.*?:\s+(.*)/\1/' | sed -e 's/\",//g' | sed -e 's/\"//g')
export PKI_EMAIL_FROM=$(grep from $adminDir/data/config.json | head -1 | perl -p0e 's/.*?:\s+(.*)/\1/' | sed -e 's/\",//g' | sed -e 's/\"//g')

../gui/apply-boulder
cd ..

cp docker/docker-compose.yml .
docker-compose up