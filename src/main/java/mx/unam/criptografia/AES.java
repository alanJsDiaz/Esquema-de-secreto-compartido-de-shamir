package mx.unam.criptografia;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;

/**
 * Clase que contiene los metodos para cifrar y descifrar un archivo utilizando Advanced Encryption Standard (AES).
 */
public class AES {

    private static final String ALGORITHM = "AES";

    /**
     * Método para cifrar un archivo utilizando Advanced Encryption Standard (AES).
     * @param archivoConContrasenas El nombre del archivo en el que seran guardadas las n contraseñas.
     * @param archivoDocumentoClaro El nombre del archivo con el documento claro.
     * @param contrasena Contraseña.
     */
    public static void cifrar(String archivoConContrasenas, String archivoDocumentoClaro, byte[] contraseña, int numeroTotalEvaluaciones, int minimoEvaluaciones) {
        try {
            SecretKeySpec key = generarClaveAES(contraseña);
    
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
    
            File archivoClaro = new File(archivoDocumentoClaro);
            byte[] datosClaros = Files.readAllBytes(archivoClaro.toPath());
    
            byte[] datosCifrados = cipher.doFinal(datosClaros);
    
            File archivoCifrado = new File(archivoConContrasenas + ".aes");
            try (FileOutputStream fos = new FileOutputStream(archivoCifrado)) {
                fos.write(numeroTotalEvaluaciones);
    
                fos.write(minimoEvaluaciones);
    
                byte[] nombreArchivoClaroBytes = archivoClaro.getName().getBytes();
                fos.write(nombreArchivoClaroBytes.length); 
                fos.write(nombreArchivoClaroBytes);
    
                // Escribir los datos cifrados
                fos.write(datosCifrados);
            }
            System.out.println("Archivo cifrado exitosamente :) ");
        } catch (Exception e) {
            System.err.println("Error al cifrar el archivo: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    
    
    
    

    /**
     * Método para descifrar un archivo cifrado utilizando Advanced Encryption Standard (AES).
     * @param archivoConContrasenas El nombre del archivo con las contraseñas necesarias.
     * @param archivoCifrado El nombre del archivo cifrado.
     */
    public static void descifrar(String archivoConContrasenas, String archivoCifrado) {
    try {
        // Leer el archivo cifrado
        File archivoCifradoFile = new File(archivoCifrado);
        byte[] datosCifrados = Files.readAllBytes(archivoCifradoFile.toPath());

        // Leer la información básica desde el archivo cifrado
        int numeroTotalEvaluaciones = datosCifrados[0];  // Número total de fragmentos (n)
        int minimoEvaluaciones = datosCifrados[1];       // Número mínimo de fragmentos necesarios para recuperar el secreto (t)
        
        // Leer el nombre del archivo original
        int nombreArchivoClaroLongitud = datosCifrados[2];
        String nombreArchivoClaro = new String(
            datosCifrados, 3, nombreArchivoClaroLongitud
        );

        // Leer los datos cifrados reales (los datos del archivo cifrado)
        byte[] datosRealesCifrados = Arrays.copyOfRange(
            datosCifrados, 3 + nombreArchivoClaroLongitud, datosCifrados.length
        );

        // Recuperar la contraseña (secreto compartido) utilizando Shamir
        byte[] contrasena = SecretoShamir.recuperaSecreto(archivoConContrasenas);
        SecretKeySpec key = generarClaveAES(contrasena);

        // Obtener los puntos (fragmentos) desde el archivo de fragmentos
        List<BigInteger[]> evaluaciones = SecretoShamir.obtenerPuntos(archivoConContrasenas);

        // Verificar si el número de puntos es suficiente según el valor de t (mínimo número de puntos)
        if (evaluaciones.size() < minimoEvaluaciones) {
            throw new IllegalArgumentException("El archivo con evaluaciones no contiene el número mínimo necesario de puntos (t=" + minimoEvaluaciones + ").");
        }

        // Inicializar el cifrador AES para desencriptar los datos
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] datosDescifrados = cipher.doFinal(datosRealesCifrados);

        // Escribir el archivo descifrado
        File archivoDescifrado = new File(nombreArchivoClaro);
        try (FileOutputStream fos = new FileOutputStream(archivoDescifrado)) {
            fos.write(datosDescifrados);
        }
        System.out.printf("Archivo descifrado exitosamente y guardado en: %s (n=%d, t=%d)%n", 
            archivoDescifrado.getName(), numeroTotalEvaluaciones, minimoEvaluaciones);
    } catch (Exception e) {
        System.err.println("Error al descifrar el archivo: " + e.getMessage());
        e.printStackTrace();
    }
}



    /**
     * Genera una clave AES de 256 bits a partir de la contraseña.
     * @param contrasena Contraseña en formato de bytes.
     * @return Clave AES.
     * @throws Exception Si ocurre un error durante la generacion de la clave.
     */
    private static SecretKeySpec generarClaveAES(byte[] contrasena) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] clave = sha.digest(contrasena);

        clave = Arrays.copyOf(clave, 32); 
        return new SecretKeySpec(clave, ALGORITHM);
    }
}
