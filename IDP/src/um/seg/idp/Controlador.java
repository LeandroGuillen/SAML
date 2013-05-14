package um.seg.idp;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.xml.io.MarshallingException;

public class Controlador extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private final String URL_RECURSO = "recurso";
	private final String URL_RAIZ = "idp";

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
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
				html += "<h1>Bienvenido a Identity Provider</h1>";
				html += "<p>He recibido esto del Service Provider</p>";
				html += "<p>" + samlReq + "</p>";

			} else if (pagina.equalsIgnoreCase(URL_RECURSO)) {
				// Se ha pedido un recurso
				html = solicitarRecurso(html);

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

		} catch (MarshallingException ex) {
			Logger.getLogger(Controlador.class.getName()).log(Level.SEVERE, null, ex);
		} finally {
			out.close();
		}
		response.setContentType("text/html;charset=UTF-8");
	}

	private String solicitarRecurso(String html) throws MarshallingException {
		AuthnRequest ar = SAMLUtil.createAuthNRequest("sp.seg.um", "idp.seg.um", "sp.seg.um/SP/controlador");
		String arString = SAMLUtil.SAMLtoString(ar);

		html += "<form id=\"formulario\" action=\"http://idp.seg.um:8080/IDP\" method=\"post\">" + "<input type=\"hidden\" name=\"SAMLRequest\" value=\"valorSAML\"/>"
				+ "<input type=\"submit\" value=\"\"/>" + "</form>" + "<script> var formulario = document.getElementById('formulario'); formulario.submit(); </script>";

		return html;
	}

	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doGet(request, response);
	}
}
