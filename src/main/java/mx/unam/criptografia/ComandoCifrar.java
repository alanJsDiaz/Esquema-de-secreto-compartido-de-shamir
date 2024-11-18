package mx.unam.criptografia;

/**
 * Comando para cifrar un archivo.
 */
public class ComandoCifrar implements Comando {
    private String archivoConContraseñas;
    private String archivoDocumentoClaro;
    private byte[] contraseña;

    /**
     * Constructor. 
     * @param archivoConContraseñas Nombre del archivo en el que serán guardadas las n contraseñas.
     * @param archivoDocumentoClaro Nombre del archivo con el documento claro.
     * @param contraseña Contraseña.
     */
    public ComandoCifrar(String archivoConContraseñas, String archivoDocumentoClaro, byte[] contraseña) {
        this.archivoConContraseñas = archivoConContraseñas;
        this.archivoDocumentoClaro = archivoDocumentoClaro;
        this.contraseña = contraseña;
    }

    /**
     * Ejecuta el comando.
     */
    @Override
    public void ejecutar() {
        System.out.println("Cifrando...");
        AES.cifrar(archivoConContraseñas, archivoDocumentoClaro, contraseña);
        System.out.println("Texto cifrado: " + archivoConContraseñas + ".aes\n" + "Contraseñas: " + archivoConContraseñas + ".frg");
    }
}