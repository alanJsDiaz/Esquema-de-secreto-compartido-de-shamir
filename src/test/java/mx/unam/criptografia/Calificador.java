package mx.unam.criptografia;

import java.util.Iterator;
import java.util.Random;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.rules.TestName;

import java.text.DecimalFormat;

/**
 * Clase base que se encarga en crear la aplicación para el manejo y uso de
 * pruebas unitarias.
 *
 * Las pruebas se definen en clases hijas de esta clase, y deben sobrescribir el
 * método init. Para empezar cada prueba se debe utilizar los métodos iniciaPrueba
 * y deben finalizar con el método passed, mientras que el aumento de aciertos
 * por prueba unitaria se hace con el método addUp.
 */
public abstract class Calificador {

	/**
	 * Rango para pruebas de longitud cortas.
	 */
	public static final int RANGO_CORTO = 4;

	/**
	 * Rango para pruebas de longitud media.
	 */
	public static final int RANGO_MEDIO = 16;

	/**
	 * Rango para pruebas de longitud larga.
	 */
	public static final int RANGO_LARGO = 256;

	/**
	 * Longitud de las cadenas de resumen antes del retorno de carro.
	 */
	public static final int LONGITUD = 75;

	/**
	 * Puntos acumulados en la prueba actual.
	 */
	protected static double puntos;

	/**
	 * Puntos totales en la prueba actual.
	 */
	protected static double numeroDePuntos;

	
	/**
	 * Iterador de rsg.
	 */
	protected static Iterator<String> rsgIt;

	/**
	 * Cantidad de elementos que rsg tendrá.
	 */
	protected static int rango;

	/**
	 * Generador de números aleatorios.
	 */
	protected static Random rdm;

	/**
	 * Indica si ya se imprimió el reporte de la ultima prueba ejecutada.
	 */
	protected static boolean estaImpreso;

	/**
	 * Define el nombre de la categoría de la prueba en ejecución.
	 */
	protected static String nombreDeCategoria;

	/**
	 * Definición de las categorías a calificar.
	 */
	protected static Categoria[] categorias;
	
	/**
	 * Limita el número de decimales imprimibles a dos.
	 */
	private static final DecimalFormat df = new DecimalFormat("0.00");

	/**
	 * Constructor por defecto. Define la cantidad de números posibles igual a
	 * {@value #RANGO_MEDIO}. Con una sola categoría a calificar con 1.0 de 1.0
	 * aciertos. Permite referencias nulas.
	 */
	public Calificador() {
		init();
		setCategorias();
		rdm = new Random();
	}

	/**
	 * Define que al inicio de cada prueba se guarde el nombre de dicha prueba.
	 */
	@Rule
	public TestName nombreDePrueba = new TestName();

	/**
	 * Método que se implementa para mantener correcta la creación de las clases
	 * que definen a las pruebas unitarias.
	 *
	 * Se espera que las clases hijas sobrescriban este método, pues funge como
	 * constructor para todas las clases en la jerarquía de herencia de esta
	 * clase.
	 */
	protected void init() {
	}

	/**
	 * Define las categorías a calificar.
	 *
	 * Se espera que las clases hijas sobrescriban este método.
	 *
	 * Por defecto solo se tiene una categoría a calificar sin nombre y con 1.0
	 * de 1.0 aciertos.
	 */
	protected void setCategorias() {
		defineCategorias(new String[]{
			""
		}, new double[]{
			1.0
		});
	}

	/**
	 * Define las categorías a calificar, recibe dos arreglos de misma longitud,
	 * uno con los nombres de cada categoría y el otro con los porcentajes. La
	 * suma de dichos porcentajes debe ser iguala uno.
	 *
	 * @param nombreDeCategorias String[] Contiene los nombres de las categorías.
	 * @param porcentajes double[] Contiene la ponderación de las categorías.
	 */
	protected void defineCategorias(String[] nombreDeCategorias, double[] porcentajes) {
		Categoria[] c;
		nombreDeCategoria = "";
		c = new Categoria[nombreDeCategorias.length];
		for (int i = 0; i < c.length; i++) {
			c[i] = new Categoria(nombreDeCategorias[i], porcentajes[i]);
		}

		/**
		 * Aquí se revisa si las categorías ya se definieron con anterioridad,
		 * esto es porque JUnit "crea" de nuevo una instancia de Calificador
		 * cada que ejecuta una prueba.
		 */
		if (categorias == null) {
			categorias = c;
		} else if (c.length != categorias.length) {
			categorias = c;
		} else {
			for (int i = 0; i < c.length; i++) {
				if (!c[i].equals(categorias[i])) {
					categorias = c;
					break;
				}
			}
		}
	}

	/**
	 * Se ejecuta antes de iniciar la ejecución de todas las pruebas. Inicia los
	 * puntos obtenidos y a calificar en cero e inicia las banderas en su estado
	 * inicial.
	 */
	@BeforeClass
	public static void setUpClass() {
		puntos = numeroDePuntos = 0.0;
		estaImpreso = true;
	}

	/**
	 * Se ejecuta al finalizar la ejecución de todas las pruebas. Imprime el
	 * ultimo reporte y el puntaje total obtenido.
	 */
	@AfterClass
	public static void tearDownClass() {
		imprime(true, getPuntuajeFinal());
	}

	/**
	 * Define el inicio de una prueba en particular. Los parámetro definidos se
	 * utilizan para categorizar cada tipo de prueba, así como los aciertos de
	 * la prueba.
	 *
	 * @param s String Es la descripción de la prueba en particular.
	 * @param p double Es el puntaje máximo que se obtiene por esta prueba.
	 */
	public final void inicioPrueba(String s, double p) {
		imprime(true, nombreDePrueba.getMethodName() + ":\n\t" + formateandoString(s, LONGITUD));
		numeroDePuntos = p;
		puntos = 0.0;
		estaImpreso = false;
		addMax(p, nombreDeCategoria);
	}

	/**
	 * Define el inicio de una prueba en particular. Los parámetro definidos se
	 * utilizan para categorizar cada tipo de prueba, así como los aciertos de
	 * la prueba.
	 *
	 * @param s String Es la descripción de la prueba en particular.
	 * @param p double Es el puntaje máximo que se obtiene por esta prueba.
	 * @param c String Es el nombre de la categoría de la prueba.
	 */
	public final void inicioPrueba(String s, double p, String c) {
		nombreDeCategoria = c;
		inicioPrueba(s, p);
	}

	/**
	 * Se invoca para aumentar el puntaje obtenido para la prueba, el puntaje se
	 * agrega a la categoría de la prueba.
	 *
	 * No revisa correctez.
	 *
	 * @param d double Es el aumento en el puntaje obtenido para la prueba.
	 */
	public final void agregaPuntos(double d) {
		puntos += d;
		agregaPuantuaje(d, nombreDeCategoria);
	}

	/**
	 * Se invoca para avisar que la prueba fue pasada con éxito.
	 */
	public final void aprobada() {
		imprime(false, "\tAprobada.");
	}


	/**
	 * Se invoca para avisar que la prueba fue pasada con éxito.
	 * @param s String Mensaje que se imprime después del resumen.
	 * @param length int Longitud de la cadena de resumen.
	 * @return String Cadena de resumen.
	 */
	public final String formateandoString(String s, int length) {
		int index;
		if (s.length() > length - 4) {
			index = s.lastIndexOf(" ", length - 4); // se usa 4 por el \t
			return s.substring(0, index) + "\n\t" + formateandoString(s.substring(index + 1), length);
		} else {
			return s;
		}
	}

	/**
	 * Imprime el resumen de la prueba si no se ha impreso ya, además imprime un
	 * mensaje en particular.
	 *
	 * @param p boolean Indica si el resumen se imprime con una vuelta de carro
	 * después de dicho resumen o no.
	 * @param msg String Mensaje que se imprime después del resumen.
	 */
	public static final void imprime(boolean p, String msg) {
		String s;
		if (!estaImpreso) {
			s = "\t[" + puntos + "/" + numeroDePuntos + "]";
			if (p) {
				System.out.println(s);
			} else {
				System.out.print(s);
			}
		}
		estaImpreso = true;
		System.out.println(msg);
	}

	/**
	 * Agrega el puntaje dado al puntaje máximo de la categoría dada.
	 *
	 * @param puntuacion double Puntaje a agregar.
	 * @param nombreDeCategoria String Nombre de la categoría a modificar.
	 */
	private void addMax(double puntuacion, String nombreDeCategoria) {
		int i;
		i = getIndiceCategoria(nombreDeCategoria);
		categorias[i].addMax(puntuacion);
	}

	/**
	 * Agrega el puntaje dado al puntaje obtenido de la categoría dada.
	 *
	 * @param puntuaje double Puntaje a agregar.
	 * @param nombreDeCategoria String Nombre de la categoría a modificar.
	 */
	private void agregaPuantuaje(double puntuaje, String nombreDeCategoria) {
		int i;
		i = getIndiceCategoria(nombreDeCategoria);
		categorias[i].agregaPuntuaje(puntuaje);
	}

	/**
	 * Obtiene el índice dentro del arreglo de categorías de la categoría que
	 * tiene el nombre dado.
	 * @param msg String Nombre de la categoría a buscar.
	 * @return int Índice de la categoría a buscada.
	 * @throws IndexOutOfBoundsException Si el nombre no se encuentra en el
	 * arreglo de categorías.
	 */
	private int getIndiceCategoria(String nombreCategoria) {
		for (int i = 0; i < categorias.length; i++) {
			if (nombreCategoria.equals(categorias[i].getNombre())) {
				return i;
			}
		}
		throw new IndexOutOfBoundsException("No existe el nombre " + nombreCategoria + " en las categorías dadas.");
	}

	/**
	 * Método que se encarga de calcular y devolver en forma de cadena los
	 * puntajes parciales para cada categoría y el puntaje general de todas las
	 * categorías.
	 *
	 * @return String Cadena que representa el resumen del total.
	 */
	private static String getPuntuajeFinal() {
		double d, n, puntuaje, maxPuntuaje, porcentaje;
		String name, str1, str2;
		Impresora p;
		StringBuilder sb;
		p = new Impresora(LONGITUD);
		sb = new StringBuilder();
		d = 0.0;
		for (int i = 0; i < categorias.length; i++) {
			puntuaje = categorias[i].getPuntuaje();
			maxPuntuaje = categorias[i].getPuntosMaximos();
			porcentaje = categorias[i].getPorcentaje();
			name = categorias[i].getNombre();
			n = (puntuaje / maxPuntuaje * porcentaje);
			d = (Double.isNaN(n) ? d : d + n);
			sb.append(p.divisor('='));
			sb.append("\n");
			str1 = name + " (Aciertos: " + df.format(puntuaje) + "/" + df.format(maxPuntuaje) + ")";
			str2 = "Puntaje: " + df.format(n * 100.0) + "/" + (porcentaje * 100.0);
			sb.append(p.linea(str1, str2));
			sb.append("\n");
		}

		sb.append(p.divisor('='));
		sb.append("\n");
		str1 = "Puntaje Total:";
		str2 = df.format(d * 100.0) + "/100.0";
		sb.append(p.linea(str1, str2));
		sb.append("\n");
		sb.append(p.divisor('='));

		return sb.toString();
	}
}
