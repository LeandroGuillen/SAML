package um.seg.sp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.impl.RandomIdentifierGenerator;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class ControladorSP extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private final String URL_RECURSO = "recurso";
	private final String URL_RAIZ = "sp";
	private final String URL_IDP = "http://idp.seg.um:8080/idp"; // http://idp.seg.um:8080/IDP
	private final String PRECIADO_RECURSO = "http://25.media.tumblr.com/tumblr_m78a4nePqV1r3qwdqo1_500.gif";

	public ControladorSP() {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			e.printStackTrace();
		}
	}

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

		response.setContentType("text/html;charset=UTF-8");
		PrintWriter out = response.getWriter();

		// Obtener pagina visitada
		String[] trozosURL = request.getRequestURI().split("/");
		String pagina = trozosURL[trozosURL.length - 1];
		String html = "";

		// Construyendo parte superior del fichero HTML
		html += "<!DOCTYPE html><html><head><title>Service Provider</title></head><body>";

		// Obtener la sesion del cliente, crearla si fuera necesario (true)
		HttpSession session = request.getSession(true);

		if (pagina.equalsIgnoreCase(URL_RAIZ)) {

			// Pagina raiz
			html = tratarPaginaRaiz(session, html);

		} else if (pagina.equalsIgnoreCase(URL_RECURSO)) {

			// Se ha pedido un recurso
			html = tratarPeticionRecurso(session, request, html);

		} else {

			// Se ha pedido cualquier otra cosa
			html += "<h1>Bienvenido a Service Provider</h1>";
			html += "<h2>Error 404</h2>" + "<p>La pagina '" + pagina + "' no existe</p>";
			html += "<p><a href=\"/sp/\">Volver al inicio</a></p>";

		}

		// Fin del fichero HTML
		html += "</body></html>";
		// Volcar en la salida
		out.println(html);
		out.close();

	}

	private String tratarPaginaRaiz(HttpSession session, String html) {
		Object sessionAssertion = session.getAttribute("assertion");
		if (session.isNew() || sessionAssertion == null) {
			// Estamos en la pagina raiz
			html += "<h1>Bienvenido a Service Provider</h1>";
			html += "<p>Haz click <a href=\"/sp/recurso\">aqui</a> para obtener el recurso.</p>";
		} else {
			Assertion assertion = (Assertion) sessionAssertion;
			NameID nameID = assertion.getSubject().getNameID();
			String nombre = nameID.getValue() + "@" + nameID.getNameQualifier();
			html += "<h1>Bienvenido a Service Provider, " + nombre + "</h1>";
			html += "<p>Haz click <a href=\"/sp/recurso\">aqui</a> para obtener el recurso.</p>";
		}
		return html;
	}

	private String tratarPeticionRecurso(HttpSession session, HttpServletRequest request, String html) {
		try {
			String stringResponse = request.getParameter("SAMLResponse");
			if ((session.isNew() || stringResponse == null) && session.getAttribute("assertion") == null) {
				// Es la primera vez que el usuario intenta acceder al
				// recurso, hay que crear un Authentication Request y
				// redirigirlo al Identity Provider.
				AuthnRequest ar = createAuthNRequest("sp.seg.um:8080", "idp.seg.um:8080", "sp.seg.um:8080/sp/recurso");
				String arString = SAMLtoString(ar);
				arString = arString.replaceAll("\"", "'");

				html += "<form id=\"formulario\" action=\"" + URL_IDP + "\" method=\"post\">" + "<input type=\"hidden\" name=\"SAMLRequest\" value=\"" + arString
						+ "\"/><input type=\"submit\" value=\"\"/ style=\"display:hidden\">" + "</form><h2>Redirigiendo...</h2>"
						+ "<script> var formulario = document.getElementById('formulario'); formulario.submit(); </script>";
			} else if (session.getAttribute("assertion") != null) {
				// Aqui tenemos un assertion en la sesion, es decir, ya hemos
				// sido autenticados con exito anteriormente

				// Comprobar que el AuthenticationStatement es aun valido

				// Mostrar recurso
				Assertion assertion = (Assertion) session.getAttribute("assertion");
				NameID nameID = assertion.getSubject().getNameID();
				String nombre = nameID.getValue() + "@" + nameID.getNameQualifier();
				// String assertionIssuedBy =
				// samlResponse.getIssuer().getValue();

				html += "<h1>Preciado Recurso</h1><p>Bienvenido, " + nombre + ". Aquí tienes el tan preciado recurso:</p><img width=\"400px\" src = \"" + PRECIADO_RECURSO + "\" />";
			} else {

				// Si estamos aqui es porque el usuario ya ha estado antes, pero
				// no ha sido autenticado. Es porque viene redirigido del IDP.

				// Leer response del IDP
				Response samlResponse = (Response) stringToSAML(stringResponse);

				// Comprobar que el IDP autentico al usuario correctamente
				if (samlResponse != null && samlResponse.getStatus().getStatusCode().getValue().equals(StatusCode.SUCCESS_URI)) {
					// Permitir acceder al recurso

					Assertion assertion = samlResponse.getAssertions().get(0);
					NameID nameID = assertion.getSubject().getNameID();
					String nombre = nameID.getValue() + "@" + nameID.getNameQualifier();
					String assertionIssuedBy = samlResponse.getIssuer().getValue();

					html += "<p>Assertion issued by " + assertionIssuedBy + "</p>";
					html += "<h1>Preciado Recurso</h1><p>Bienvenido, " + nombre + ". Aquí tienes el tan preciado recurso:</p><img width=\"400px\" src = \"" + PRECIADO_RECURSO + "\" />";

					// Guardar el assertion en el contexto de sesion del
					// usuario
					session.setAttribute("assertion", assertion);

				} else {
					// No se autentico correctamente
				}
			}

		} catch (XMLParserException e) {
			html += "<h1>Service Provider</h1><p>Error al parsear el XML</p>";
		} catch (UnmarshallingException e) {
			html += "<h1>Service Provider</h1><p>Error al deserializar el objeto Authentication Request.</p>";
		} catch (MarshallingException e) {
			html += "<h1>Service Provider</h1><p>Error al serializar el objeto Response.</p>";
		} catch (UnsupportedEncodingException e) {
			html += "<h1>Service Provider</h1><p>Error al serializar el objeto Response.</p>";
		}
		return html;
	}

	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doGet(request, response);
	}

	@SuppressWarnings("rawtypes")
	private AuthnRequest createAuthNRequest(String issuerId, String destination, String responseURL) {
		// Create BuilderFactory
		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		// Create AuthnRequest
		SAMLObjectBuilder builder = (SAMLObjectBuilder) builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
		AuthnRequest authnRequest = (AuthnRequest) builder.buildObject();
		authnRequest.setVersion(SAMLVersion.VERSION_20);
		authnRequest.setIssueInstant(new DateTime());
		authnRequest.setID(new RandomIdentifierGenerator().generateIdentifier());
		// Set Issuer
		builder = (SAMLObjectBuilder) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Issuer issuer = (Issuer) builder.buildObject();
		issuer.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:entity");
		issuer.setValue(issuerId);
		authnRequest.setIssuer(issuer);
		// Set destination
		authnRequest.setDestination(destination);
		// Set response URL
		authnRequest.setAssertionConsumerServiceURL(responseURL);

		return authnRequest;
	}

	private String SAMLtoString(XMLObject object) throws MarshallingException {
		MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
		Marshaller marshaller = marshallerFactory.getMarshaller(object);
		org.w3c.dom.Element subjectElement = marshaller.marshall(object);
		return XMLHelper.prettyPrintXML(subjectElement);
	}

	private SAMLObject stringToSAML(String samlObject) throws UnsupportedEncodingException, XMLParserException, UnmarshallingException {
		InputStream is = new ByteArrayInputStream(samlObject.getBytes("UTF8"));
		BasicParserPool parser = new BasicParserPool();
		Document doc = parser.parse(is);
		Element samlElement = doc.getDocumentElement();
		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(samlElement);
		return (SAMLObject) unmarshaller.unmarshall(samlElement);
	}
}
