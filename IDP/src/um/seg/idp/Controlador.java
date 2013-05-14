package um.seg.idp;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.XMLParserException;

public class Controlador extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private final String URL_RECURSO = "recurso";
	private final String URL_RAIZ = "idp";

	public Controlador() {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			e.printStackTrace();
		}
	}

	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		PrintWriter out = response.getWriter();

		// Obtener pagina visitada
		String[] trozosURL = request.getRequestURI().split("/");
		String pagina = trozosURL[trozosURL.length - 1];

		try {
			// Construyendo parte superior del fichero HTML
			String html = "";
			html += "<!DOCTYPE html><html><head><title>Identity Provider</title></head><body>";

			// Comprobamos donde esta queriendo acceder el cliente
			if (pagina.equalsIgnoreCase(URL_RAIZ)) {
				// Estamos en la pagina raiz
				String samlReq = request.getParameter("SAMLRequest");
				samlReq = samlReq.replaceAll("'", "\"");
				AuthnRequest ar = (AuthnRequest) SAMLUtil.stringToSAML(samlReq);

				html += "<h1>Bienvenido a Identity Provider</h1>";
				html += "<p>He recibido esto del Service Provider</p>";
				html += "<pre>" + samlReq + "</pre>";

			} else if (pagina.equalsIgnoreCase(URL_RECURSO)) {
				// Se ha pedido un recurso

			} else {
				// Se ha pedido cualquier otra cosa
				html += "<h1>Bienvenido a Service Provider</h1>";
				html += "<p>La pagina '" + pagina + "' no esta reconocida</p>";
				html += "<p><a href=\"/sp/\">Volver al inicio</a></p>";
			}

			// Fin del fichero HTML
			html += "</body></html>";
			// Volcar en la salida
			out.println(html);

		} catch (XMLParserException e) {
			e.printStackTrace();
		} catch (UnmarshallingException e) {
			e.printStackTrace();
		} finally {
			out.close();
		}
		response.setContentType("text/html;charset=UTF-8");
	}

	@Override
	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		doGet(request, response);
	}
}
