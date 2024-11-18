package mx.unam.criptografia;

/**
 * Define la clase que guarda las categorías a calificar.
 *
 * Se utiliza una cadena String como identificador para diferenciar cada
 * categoría distinta. Cada categoría requiere de un porcentaje entre cero y
 * uno. El puntaje máximo y el puntaje obtenido se calcula en tiempo de
 * ejecución al pasar o fallar cada prueba correspondiente a esta categoría.
 *
 */
public class Categoria {

	/**
	 * Define el nombre de la esta categoría.
	 */
	private String nombre;

	/**
	 * Define el porcentaje que esta categoría vale con respecto al total.
	 */
	private double porcentaje;

	/**
	 * Define el número total de puntos en esta categoría.
	 */
	private double puntosMaximos;

	/**
	 * Define el número de aciertos con respecto al total en esta categoría.
	 */
	private double puntuaje;

	/**
	 * Constructor.
	 *
	 * @param nombre String Nombre de esta categoría.
	 * @param porcentaje double Porcentaje que vale esta categoría.
	 */
	public Categoria(String nombre, double porcentaje) {
		this.nombre = nombre;
		this.porcentaje = porcentaje;
		this.puntosMaximos = 0.0;
		this.puntuaje = 0.0;
	}

	/**
	 * Aumenta el puntaje máximo de esta categoría.
	 *
	 * @param puntosMaximos double Puntaje a agregar.
	 */
	public void addMax(double puntosMaximos) {
		this.puntosMaximos += puntosMaximos;
	}

	/**
	 * Aumenta el puntaje obtenido de esta categoría.
	 *
	 * @param puntuaje double Puntaje a agregar.
	 */
	public void agregaPuntuaje(double puntaje) {
		this.puntuaje += puntaje;
	}

	/**
	 * Método de acceso para el nombre de la categoría.
	 *
	 * @return  Nombre de esta categoría.
	 */
	public String getNombre() {
		return nombre;
	}

	/**
	 * Método de acceso para el porcentaje de la categoría.
	 *
	 * @return double Porcentaje de esta categoría.
	 */
	public double getPorcentaje() {
		return porcentaje;
	}

	/**
	 * Método de acceso para el puntaje máximo de la categoría.
	 *
	 * @return double Puntaje máximo de esta categoría.
	 */
	public double getPuntosMaximos() {
		return puntosMaximos;
	}

	/**
	 * Método de acceso para el puntaje obtenido de la categoría.
	 *
	 * @return double Puntaje obtenido de esta categoría.
	 */
	public double getPuntuaje() {
		return puntuaje;
	}

	@Override
	public boolean equals(Object obj) {
		Categoria c, t;

		if (obj == null) {
			return false;
		} else if (obj == this) {
			return true;
		} else if (!(obj instanceof Categoria)) {
			return false;
		} else {
			c = (Categoria) obj;
			t = this;

			if (!t.nombre.equals(c.nombre)) {
				return false;
			}
			if (Math.abs(t.porcentaje - c.porcentaje) > 0.1) {
				return false;
			}

			return true;
		}
	}
}
