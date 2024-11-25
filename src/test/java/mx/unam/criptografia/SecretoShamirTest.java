package mx.unam.criptografia;




import static org.junit.Assert.*;
import org.junit.Test;
import java.io.IOException;

import java.math.BigInteger;
import java.util.List;


/**
 * Clase de pruebas unitarias para la clase UtilidadEsteganografia.
 */
public class SecretoShamirTest extends Calificador {


    public SecretoShamirTest() {
    }

    @Test
    public void testGetSHA256() {
        inicioPrueba("getSHA256", 1);
        byte[] expectativa = new byte[]{
            -78, 33, -39, -37, -80, -125, -89, -13, 52, 40, -41, -62, -93, -61, 25,
            -118, -23, 37, 97, 77, 112, 33, 14, 40, 113, 108, -54, -89, -51, 77, -37, 121
        };
        byte[] resultado = ProcesadorContraseña.getSHA256("hola");
        assertArrayEquals(expectativa, resultado);
        agregaPuntos(1);
        aprobada();
    }

    @Test
    public void testGeneraPolinomio() {
    inicioPrueba("generaPolinomio", 1);
        byte[] secreto = new byte[]{1, 2, 3, 4, 5};
        List<BigInteger> coeficientes = SecretoShamir.generaPolinomio(3, secreto);
        assertEquals(3, coeficientes.size());
        agregaPuntos(1);
        aprobada();
    }

    @Test
    public void testEvaluaPolinomio() {
        inicioPrueba("evaluaPolinomio", 1);
        List<BigInteger> coeficientes = List.of(
            new BigInteger("1"),
            new BigInteger("2"),
            new BigInteger("3")
        );
        BigInteger x = new BigInteger("2");
        BigInteger resultado = SecretoShamir.evaluaPolinomioHorner(coeficientes, x);
        assertEquals(new BigInteger("17"), resultado);
        agregaPuntos(1);
        aprobada();
    }

    @Test   
    public void testGeneraPuntos() {
        inicioPrueba("generaPuntos", 1);
        List<BigInteger> coeficientes = List.of(
            new BigInteger("1"),
            new BigInteger("2"),
            new BigInteger("3")
        );
        List<BigInteger[]> puntos = SecretoShamir.generaPuntos(3, coeficientes);
        assertEquals(3, puntos.size());
        agregaPuntos(1);
        aprobada();
    }

    @Test
    public void testArchivoConContraseñas() {
        inicioPrueba("archivoConContraseñas", 1);
        String archivoConContraseñas = "src/test/java/mx/unam/criptografia/archivosTests/contraseñas";
        byte[] contraseña = ProcesadorContraseña.getSHA256("hola");
        SecretoShamir.archivoConContraseñas(archivoConContraseñas, "4", "3", contraseña);
        agregaPuntos(1);
        aprobada();
    }

    @Test
    public void testRecuperaSecreto() {
        inicioPrueba("recuperaSecreto", 1);
        String archivoConContraseñas = "src/test/java/mx/unam/criptografia/archivosTests/contraseñas-4-3.frg";
        byte[] secreto = SecretoShamir.recuperaSecreto(archivoConContraseñas);
        assertNotNull(secreto);
        agregaPuntos(1);
        aprobada();
    }
}
