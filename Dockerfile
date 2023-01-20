# To change this license header, choose License Headers in Project Properties.
# To change this template file, choose Tools | Templates
# and open the template in the editor.
FROM tomcat:9.0

USER root
RUN  mkdir -p /usr/local/tomcat/conf \
    && chown -R 1001:root  /usr/local/tomcat/conf \
    && chmod -R a+rwx /usr/local/tomcat/conf \
    && chown -R 1001:root /usr/local/tomcat/webapps \
    && chmod -R a+rwx /usr/local/tomcat/webapps \
    && chmod -R 777 /tmp/ \
    && apt-get update && apt-get -y install softhsm2 opensc && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN sed 's/ FINE/ FINEST/g; s/ INFO/ FINEST/g' -i.back /usr/local/tomcat/conf/logging.properties
RUN cat /usr/local/tomcat/conf/logging.properties

#-add-exports=jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED

RUN echo 'JAVA_OPTS="$JAVA_OPTS -Dsignvalidation.url=$SIGNING_URL -Dpkcs11.hsm_module=$HSM_MODULE -Dpkcs11.hsm_slot=$HSM_SLOT -Dpkcs11.hsm_user_pin=$HSM_USER_PIN -Dpkcs11.hsm_key_id=$HSM_KEY_ID -Didp.url=$IDP_URL -Dfas.certificate_filename=$FAS_CERTIFICATE_FILENAME -Dfas.client_id=$FAS_CLIENT_ID -Dcors.allowedorigins=$CORS_ALLOWED_ORIGINS"' > /usr/local/tomcat/bin/setenv.sh

ADD ./esealing-ws/target/*.war /usr/local/tomcat/webapps/esealing.war
RUN chmod o+rx /var/lib/softhsm && chmod o+rx /var/lib/softhsm/tokens && chmod o+rx /etc/softhsm && chmod -R o+r /etc/softhsm

USER 1001

