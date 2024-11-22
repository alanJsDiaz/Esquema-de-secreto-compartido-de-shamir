# Esquema de Secreto Compartido de Shamir
Este proyecto implementa el Esquema de Secreto de Shamir, un método criptográfico que permite dividir un secreto en varias partes (o fragmentos)
de forma que solo un número mínimo de ellas sea necesario para recuperar el secreto completo.El esquema se basa en la construcción de un polinomio
aleatorio de grado t-1, donde 𝑡 es el número mínimo de partes necesarias para reconstruir el secreto.
Cada fragmento corresponde a un punto del polinomio, y se necesitan al menos t fragmentos para aplicar interpolación de Lagrange y recuperar el secreto.
Asi mismo se hace uso de algoritmo de cifrado simetrico AES-256 (Advanced Encryption Standard con una clave de 256 bits), de tal manera que el secreto 
compartido es utlizado como la llave para hacer la encriptación en AES-256.


## Requisitos

## Requisitos
- Java 1.8 o superior
- Maven

## Instalación
1. Clona el repositorio en tu máquina local:
   git clone https://github.com/alanJsDiaz/Esquema-de-secreto-compartido-de-shamir.git

2. Accede al directorio del proyecto:
   cd esquema-de-secreto-compartido-de-shamir


3. Compila el proyecto usando Maven:
   mvn compile

4. Empaqueta el proyecto:
   mvn package

   Esto generará un archivo `criptografia.jar` en el directorio `target`.

## Uso

### Comandos

El programa permite dos comandos principales:

1. **Cifrar**  
   Utiliza la bandera '-c' junto con el nombre del archivo donde se guardaran las contraseñas, número total de contraseñas, número minimo de contraseñas para descifrar y nombre del archivo con el documento claro.

   java -jar target/criptografia.jar -c <Nombre del archivo donde se guardaran las contraseñas> <Número total de contraseñas> <Número minimo de contraseñas para descifrar> <Nombre del archivo con el documento claro>


2. **Descifrar**  
   Utiliza la bandera `-d` junto con el archivo con contraseñas y el archivo_cifrado.

   java -jar target/criptografia.jar -d <archivo_con_contraseñas> <archivo_cifrado>


### Ejemplos
1. **Cifrar**:
   java -jar target/criptografia.jar -c Contraseñas 10 8 TextoACifrar.txt

2. **Descifrar**:
   java -jar target/criptografia.jar -d Contraseñas.frg TextoACifrar.aes

## Pruebas
El proyecto incluye dependencias para JUnit en el archivo `pom.xml`. Puedes ejecutar las pruebas unitarias con el siguiente comando:
    mvn test
