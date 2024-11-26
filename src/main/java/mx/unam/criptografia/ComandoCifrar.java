package mx.unam.criptografia;

/**
 * Comando para cifrar un archivo.
 */
public class ComandoCifrar implements Comando {
    private String archivoConContraseñas;
    private String archivoDocumentoClaro;
    private byte[] contraseña;
    private int numeroTotalEvaluaciones;
    private int minimoEvaluaciones;

    /**
     * Constructor.
     * @param archivoConContraseñas Nombre del archivo en el que serán guardadas las n contraseñas.
     * @param archivoDocumentoClaro Nombre del archivo con el documento claro.
     * @param contraseña Contraseña.
     * @param numeroTotalEvaluaciones Número total de evaluaciones.
     * @param minimoEvaluaciones Número mínimo de evaluaciones necesarias para descifrar.
     */
    public ComandoCifrar(String archivoConContraseñas, String archivoDocumentoClaro, byte[] contraseña, int numeroTotalEvaluaciones, int minimoEvaluaciones) {
        this.archivoConContraseñas = archivoConContraseñas;
        this.archivoDocumentoClaro = archivoDocumentoClaro;
        this.contraseña = contraseña;
        this.numeroTotalEvaluaciones = numeroTotalEvaluaciones;
        this.minimoEvaluaciones = minimoEvaluaciones;
    }

    /**
     * Ejecuta el comando.
     */
    @Override
    public void ejecutar() {
        System.out.println("Cifrando...");
        // Llamar al método cifrar de AES con los nuevos parámetros
        AES.cifrar(archivoConContraseñas, archivoDocumentoClaro, contraseña, numeroTotalEvaluaciones, minimoEvaluaciones);
        System.out.println("Texto cifrado y guardado en : " + archivoConContraseñas + ".aes\n" +
                "Fragmentos guardados en : " + archivoConContraseñas + ".frg");
    }
}
