package um.seg.idp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.LinkedList;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
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

import um.seg.idp.SAMLWriter.SAMLInputContainer;

public class ControladorIDP extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private final String URL_RAIZ = "idp";
	private final String URL_IDP = "http://idp.seg.um:8080/idp";
	private final String URL_IDENTIFICAR = "identificar";
	private final String USUARIO = "paco";
	private final String PASSWORD = "123";

	public ControladorIDP() {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			e.printStackTrace();
		}
	}

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		PrintWriter out = response.getWriter();

		// Obtener pagina visitada
		String[] trozosURL = request.getRequestURI().split("/");
		String pagina = trozosURL[trozosURL.length - 1];
		String html = "";

		try {
			// Construyendo parte superior del fichero HTML
			html += "<!DOCTYPE html><html><head><title>Identity Provider</title></head><body>";

			if (pagina.equalsIgnoreCase(URL_RAIZ)) {
				// Estamos en la pagina raiz
				String samlReq = request.getParameter("SAMLRequest");

				if (samlReq != null) {
					// Obtener la sesion del cliente
					HttpSession session = request.getSession(true);
					samlReq = samlReq.replaceAll("'", "\"");
					AuthnRequest ar = (AuthnRequest) stringToSAML(samlReq);
					DateTime issueInstant = ar.getIssueInstant();
					// SAMLVersion version = ar.getVersion(); // version 2.0
					String requestId = ar.getID();
					String destination = ar.getDestination();
					String assertionConsumerServiceURL = ar.getAssertionConsumerServiceURL();
					String issuerId = ar.getIssuer().getValue();
					String nameQualifier = ar.getIssuer().getNameQualifier();
					
					if (session.getAttribute("stringResponse") == null) {
						// El usuario se quiere autenticar por primera vez o no
						// esta autenticado.
						session.setAttribute("requestId", requestId);
						session.setAttribute("destination", destination);
						session.setAttribute("assertionConsumerServiceURL", assertionConsumerServiceURL);
						session.setAttribute("issuerId", issuerId);
						session.setAttribute("issueInstant", issueInstant);
						session.setAttribute("nameQualifier", nameQualifier);

						// Presentamos un formulario y que nos diga quien es
						html += "<h1>Bienvenido a Identity Provider</h1><p>Por favor, indentifiquese:</p>";
						html += "<form id=\"formulario\" action=\"/idp/" + URL_IDENTIFICAR + "\" method=\"post\">" + "Usuario:<input type=\"text\" name=\"user\"></br>"
								+ "Contraseña:<input type=\"password\" name=\"pass\"></br>" + "<input type=\"submit\" value=\"Identificar\"/></form><p>Esta peticion viene de " + issuerId + "</p>";
					} else {
						// Ya fue autenticado con anterioridad
						// Devolver el Response
						SAMLInputContainer input = new SAMLInputContainer();
						input.setStrIssuer(issuerId); // service provider
						input.setStrNameID(USUARIO); // nombre del usuario en su
													// dominio
						input.setStrNameQualifier("seg.um"); // dominio del
																// usuario
						input.setSessionId(requestId); // sesion entre usuario y
														// IDP
														// (la misma que con el
														// SP
														// nos vale)
						Assertion assertion = SAMLWriter.buildDefaultAssertion(input);

						List<Assertion> assertions = new LinkedList<Assertion>();
						assertions.add(assertion);
						Response samlResponse = createResponse(issuerId, requestId, destination, assertions);
						String stringResponse = SAMLtoString(samlResponse);
						stringResponse = stringResponse.replaceAll("\"", "'");
						
						String address = "http://" + assertionConsumerServiceURL;

						html += "<p style=\"color:green\">Autenticacion OK. Redirigiendo... </p>";
						html += "<form id=\"formulario\" action=\"" + address + "\" method=\"post\">" + "<input type=\"hidden\" name=\"SAMLResponse\" value=\"" + stringResponse
								+ "\"/><input type=\"submit\" value=\"\"/ style=\"display:hidden\">" + "</form><h2>Redirigiendo...</h2>"
								+ "<script> var formulario = document.getElementById('formulario'); formulario.submit(); </script>";
					}
				} else {
					// Intentando acceder directamente a esta pagina? nono!
					html += "<h1>Bienvenido a Identity Provider</h1>";
					html += "<p>Error: No has llegado por una petición de un Service Provider</p>";
				}

			} else if (pagina.equalsIgnoreCase(URL_IDENTIFICAR)) {
				// Obtener la sesion del cliente
				HttpSession session = request.getSession();

				if (session != null && !session.isNew()) {
					// Obtener datos del formulario
					String usuario = request.getParameter("user");
					String password = request.getParameter("pass");

					if (autenticacionCorrecta(usuario, password)) {
						// Obtener datos de la sesion
						// DateTime issueInstant = (DateTime)
						// session.getAttribute("issueInstant");
						String requestId = (String) session.getAttribute("requestId");
						String destination = (String) session.getAttribute("destination");
						String assertionConsumerServiceURL = (String) session.getAttribute("assertionConsumerServiceURL");
						String issuerId = (String) session.getAttribute("issuerId");
						// String nameQualifier = (String)
						// session.getAttribute("nameQualifier");

						// Construir respuesta
						SAMLInputContainer input = new SAMLInputContainer();
						input.setStrIssuer(issuerId); // service provider
						input.setStrNameID(USUARIO); // nombre del usuario en su
													// dominio
						input.setStrNameQualifier("seg.um"); // dominio del
																// usuario
						input.setSessionId(requestId); // sesion entre usuario y
														// IDP
														// (la misma que con el
														// SP
														// nos vale)

						Assertion assertion = SAMLWriter.buildDefaultAssertion(input);

						List<Assertion> assertions = new LinkedList<Assertion>();
						assertions.add(assertion);
						Response samlResponse = createResponse(issuerId, requestId, destination, assertions);
						String stringResponse = SAMLtoString(samlResponse);
						stringResponse = stringResponse.replaceAll("\"", "'");

						String address = "http://" + assertionConsumerServiceURL;

						html += "<p style=\"color:green\">Autenticacion OK. Redirigiendo... </p>";
						html += "<form id=\"formulario\" action=\"" + address + "\" method=\"post\">" + "<input type=\"hidden\" name=\"SAMLResponse\" value=\"" + stringResponse
								+ "\"/><input type=\"submit\" value=\"\"/ style=\"display:hidden\">" + "</form><h2>Redirigiendo...</h2>"
								+ "<script> var formulario = document.getElementById('formulario'); formulario.submit(); </script>";
						session.setAttribute("stringResponse", stringResponse);
					} else {
						html += "<h1>Bienvenido a Identity Provider</h1><p style=\"color:red\">¡Autenticacion incorrecta!</p><p>Por favor, indentifiquese:</p>";
						html += "<form id=\"formulario\" action=\"/idp/" + URL_IDENTIFICAR + "\" method=\"post\">" + "Usuario:<input type=\"text\" name=\"user\"></br>"
								+ "Contraseña:<input type=\"password\" name=\"pass\"></br>" + "<input type=\"submit\" value=\"Identificar\"/></form>";
						session.invalidate();
					}

				} else {
					html += "<p>Error: No has llegado por una petición de un Service Provider</p>";
				}

			} else {
				// Se ha pedido cualquier otra cosa
				html += "<h1>Bienvenido a Identity Provider</h1>";
				html += "<h2>Error 404</h2>" + "<p>La pagina '" + pagina + "' no existe</p>";
			}
		} catch (XMLParserException e) {
			html += "<h1>Identity Provider</h1><p>Error al parsear el XML</p>";
		} catch (UnmarshallingException e) {
			html += "<h1>Identity Provider</h1><p>Error al deserializar el objeto Authentication Request.</p>";
		} catch (MarshallingException e) {
			html += "<h1>Identity Provider</h1><p>Error al serializar el objeto Response.</p>";
		} finally {
			// Fin del fichero HTML
			html += "</body></html>";
			// Volcar en la salida
			out.println(html);
			out.close();
		}
		response.setContentType("text/html;charset=UTF-8");
	}

	private boolean autenticacionCorrecta(String user, String password) {
		return user.equals(USUARIO) && password.equals(PASSWORD);
	}

	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doGet(request, response);
	}

	public String SAMLtoString(XMLObject object) throws MarshallingException {
		MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
		Marshaller marshaller = marshallerFactory.getMarshaller(object);
		org.w3c.dom.Element subjectElement = marshaller.marshall(object);
		return XMLHelper.prettyPrintXML(subjectElement);
	}

	public SAMLObject stringToSAML(String samlObject) throws UnsupportedEncodingException, XMLParserException, UnmarshallingException {
		InputStream is = new ByteArrayInputStream(samlObject.getBytes("UTF8"));
		BasicParserPool parser = new BasicParserPool();
		Document doc = parser.parse(is);
		Element samlElement = doc.getDocumentElement();
		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(samlElement);
		return (SAMLObject) unmarshaller.unmarshall(samlElement);
	}

	@SuppressWarnings("rawtypes")
	public Response createResponse(String issuerId, String requestId, String destination, List<Assertion> assertions) {
		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		// Create Response
		SAMLObjectBuilder builder = (SAMLObjectBuilder) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);
		Response response = (Response) builder.buildObject();
		// Set request Id
		response.setInResponseTo(requestId);
		// Set Issuer
		Issuer issuer = new IssuerBuilder().buildObject();
		issuer.setValue(URL_IDP);
		response.setIssuer(issuer);
		response.setIssueInstant(new DateTime());

		// Set status code and message
		StatusCode statusCode = new StatusCodeBuilder().buildObject();
		statusCode.setValue(StatusCode.SUCCESS_URI);
		StatusMessage statusMessage = new StatusMessageBuilder().buildObject();
		statusMessage.setMessage("OK");
		builder = (SAMLObjectBuilder) builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME);
		Status responseStatus = (Status) builder.buildObject();
		responseStatus.setStatusCode(statusCode);
		responseStatus.setStatusMessage(statusMessage);
		response.setStatus(responseStatus);

		// Include assertions
		response.getAssertions().addAll(assertions);
		// response.getEncryptedAssertions().addAll(encryptedAssertions);
		// Set destination
		response.setDestination(destination);
		return response;
	}
}
