Steps:-


1) Generate Public key(X.509 Cert) and Private Key (PKCS8 format)
openssl genrsa 2048 > private.key
The first command will generate a 2048 bit (recommended) RSA private key


openssl req -new -x509 -nodes -sha1 -days 1000 -key private.key > public.cer
The second command will create the self-signed x509 certificate suitable for use on a web server.


openssl pkcs8 -topk8 -inform PEM -outform PEM -in private.key -out privateNew.pem -nocrypt
Third command is used to convert primary key from pkcs1(genrsa generates in pkcs1) format to pkcs8
Also we can convert private key in .pem format using PEMWriter from bouncycastle

