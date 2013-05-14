package um.seg.idp;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;

import org.opensaml.common.SAMLObject;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
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

/**
 *
 * @author leandro
 */
public class SAMLUtil {
	

	public static String SAMLtoString(XMLObject object) throws MarshallingException {
		MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
		Marshaller marshaller = marshallerFactory.getMarshaller(object);
		org.w3c.dom.Element subjectElement = marshaller.marshall(object);
		return XMLHelper.prettyPrintXML(subjectElement);
	}

	public static SAMLObject stringToSAML(String samlObject) throws UnsupportedEncodingException, XMLParserException, UnmarshallingException {
		InputStream is = new ByteArrayInputStream(samlObject.getBytes("UTF8"));
		BasicParserPool parser = new BasicParserPool();
		Document doc = parser.parse(is);
		Element samlElement = doc.getDocumentElement();
		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(samlElement);
		return (SAMLObject) unmarshaller.unmarshall(samlElement);
	}
}
