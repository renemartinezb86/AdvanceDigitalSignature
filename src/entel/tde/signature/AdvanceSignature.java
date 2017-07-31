package entel.tde.signature;

import SecureBlackbox.Base.*;

import SecureBlackbox.PKI.*;

import SecureBlackbox.PGP.*;

import SecureBlackbox.XML.SBXMLDefs;
import SecureBlackbox.XML.TElXMLDOMDocument;
import SecureBlackbox.XML.TElXMLDOMElement;
import SecureBlackbox.XML.TElXMLDOMNode;

import SecureBlackbox.XMLSecurity.SBXMLAdES;
import SecureBlackbox.XMLSecurity.SBXMLAdESIntf;
import SecureBlackbox.XMLSecurity.SBXMLSec;
import SecureBlackbox.XMLSecurity.TElXAdESSigner;
import SecureBlackbox.XMLSecurity.TElXMLEnvelopedSignatureTransform;
import SecureBlackbox.XMLSecurity.TElXMLKeyInfoHMACData;
import SecureBlackbox.XMLSecurity.TElXMLKeyInfoPGPData;
import SecureBlackbox.XMLSecurity.TElXMLKeyInfoRSAData;
import SecureBlackbox.XMLSecurity.TElXMLKeyInfoX509Data;
import SecureBlackbox.XMLSecurity.TElXMLReference;
import SecureBlackbox.XMLSecurity.TElXMLReferenceList;
import SecureBlackbox.XMLSecurity.TElXMLSigner;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;

import com.google.gson.JsonObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;

import java.security.cert.Certificate;

import java.sql.Ref;

import java.util.Date;
import java.util.Properties;

import javax.xml.bind.DatatypeConverter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;


public class AdvanceSignature {

    private String dllPath;
    private String licence;
    private String jniName;
    private String tokenPass;
    private String inFilePath;
    private String outFilePath;
    private String tempFilePath;
    private TElMessageSigner Signer;
    private TElPKCS11CertStorage Storage;
    private TElMemoryCertStorage CertStorage;
    private TElPKCS11SessionInfo Session;
    private TElX509Certificate Certificate;


    public static void main(String[] args) {
        AdvanceSignature advanceSignature = new AdvanceSignature();
        File file = new File(advanceSignature.inFilePath);
        JsonObject output = new JsonObject();
        try {
            InputStream myScan = new FileInputStream(file);
            byte[] b = new byte[(int) file.length()];
            myScan.read(b);
            String encoded = DatatypeConverter.printBase64Binary(b);
            output.addProperty("xml", encoded);
        } catch (Exception e) {
            e.printStackTrace();
        }
        advanceSignature.SiebelSign(output);
        /*advanceSignature.init();
        advanceSignature.load();
        //advanceSignature.sign();
        advanceSignature.Dsign();
        advanceSignature.clear();*/
    }

    private void init() {
        SBUtils.setLicenseKey(licence);
        System.loadLibrary(jniName);
        JNI.initialize();
        Signer = new TElMessageSigner();
        Storage = new TElPKCS11CertStorage();
        CertStorage = new TElMemoryCertStorage();
    }

    private void load() {
        System.out.println("dllPAth: " + dllPath);
        Storage.setDLLName(dllPath);
        Storage.open();

        int availableSlot = 0;
        for (int i = 0; i < Storage.getModule().getSlotCount(); i++) {
            TElPKCS11SlotInfo slotInfo = Storage.getModule().getSlot(i);
            if (slotInfo.getTokenPresent()) {
                availableSlot = i;
                break;
            }
        }
        Session = Storage.openSession(availableSlot, false);
        Session.login(SBPKCS11Base.utUser, tokenPass);
        Certificate = Storage.getCertificate(0);
    }

    protected boolean checkToken() {
        boolean result = true;
        try {
            init();
            load();
            if (Certificate == null) {
                result = false;
            }
        } catch (Exception e) {
            e.printStackTrace();
            result = false;
        }
        return result;
    }

    protected void Dsign() {
        TElXMLSigner Signer;
        TElXAdESSigner XAdESSigner = null;
        TElXMLKeyInfoHMACData HMACKeyData = null;
        TElXMLKeyInfoRSAData RSAKeyData = null;
        TElXMLKeyInfoX509Data X509KeyData = null;
        TElXMLKeyInfoPGPData PGPKeyData = null;
        TElFileStream F;
        FileInputStream FI;
        TElXMLDOMDocument FXMLDocument = new TElXMLDOMDocument();
        TElXMLDOMNode SigNode;
        TElXMLDOMNode selectedNode;
        byte[] Buf;
        TElXMLReference Ref = null;
        TElXMLReferenceList Refs = new TElXMLReferenceList();

        F = new TElFileStream(inFilePath, "rw", true);
        FXMLDocument.loadFromStream(F);
        selectedNode = FXMLDocument.getFirstChild();
        selectedNode = FXMLDocument;
        Signer = new TElXMLSigner();
        Signer.setSignatureType(SBXMLSec.xstEnveloped);
        Signer.setCanonicalizationMethod(SBXMLDefs.xcmCanon);
        Signer.setSignatureMethodType(SBXMLSec.xmtSig);
        Signer.setSignatureMethod(SBXMLSec.xsmRSA_SHA1);

        if (selectedNode != null) {
            Ref = new TElXMLReference();
            Ref.setDigestMethod(SBXMLSec.xdmSHA1);
            if (selectedNode instanceof TElXMLDOMDocument) {
                Ref.setURI("");
                Ref.setURINode(((TElXMLDOMDocument) selectedNode).getDocumentElement());
            } else if (selectedNode instanceof TElXMLDOMElement) {
                Ref.setURINode((TElXMLDOMNode) selectedNode);
                TElXMLDOMElement El = (TElXMLDOMElement) selectedNode;
                if (El.getAttribute("Id") != "")
                    Ref.setURI("#" + El.getAttribute("Id"));
                else if (El.getParentNode() instanceof TElXMLDOMDocument)
                    Ref.setURI("");
                else {
                    El.setAttribute("Id", "id-" + SBStrUtils.intToStr(SBRandom.sbRndGenerate(Integer.MAX_VALUE)));
                    Ref.setURI("#" + El.getAttribute("Id"));
                }
            } else {
                Ref.setURINode(selectedNode);
                Ref.setURI(selectedNode.getLocalName());
            }

            Ref.getTransformChain().add(new TElXMLEnvelopedSignatureTransform());
            Refs.add(Ref);
        }

        X509KeyData = new TElXMLKeyInfoX509Data(false);
        X509KeyData.setCertificate(Certificate);
        Signer.setKeyData(X509KeyData);
        Signer.setReferences(Refs);
        //Begin XAdES
        /*
        XAdESSigner = new TElXAdESSigner();
        Signer.setXAdESProcessor(XAdESSigner);

        XAdESSigner.setXAdESVersion(SBXMLAdES.XAdES_v1_3_2);


        XAdESSigner.getPolicyId().getSigPolicyId().setDescription("Policy Description");
        if ("tDocumentationReferenceText".compareTo("") != 0)
            XAdESSigner.getPolicyId().getSigPolicyId().getDocumentationReferences().add("tDocumentationReferenceText");
        String s = "IdentifierText";
        XAdESSigner.getPolicyId().getSigPolicyId().setIdentifier(s);
        if (s.length() > 0) {
            if (s.toLowerCase().startsWith("urn:"))
                XAdESSigner.getPolicyId().getSigPolicyId().setIdentifierQualifier(SBXMLAdES.xqtOIDAsURN);
            else
                XAdESSigner.getPolicyId().getSigPolicyId().setIdentifierQualifier(SBXMLAdES.xqtOIDAsURI);
        } else
            XAdESSigner.getPolicyId().getSigPolicyId().setIdentifierQualifier(SBXMLAdES.xqtNone);


        TElCustomCertStorage FCertStorage = new TElMemoryCertStorage();
        FCertStorage.add(Certificate, true);
        XAdESSigner.setSigningCertificates(FCertStorage);

        XAdESSigner.setSigningTime(new Date());

        // create XAdESSigner.QualifyingProperties
        XAdESSigner.generate();

        // Finally we can modify QualifyingProperties if needed
        // For example set xades prefix:
        XAdESSigner.getQualifyingProperties().setXAdESPrefix("xades");

        //end XAdES
*/
        Signer.updateReferencesDigest();

        Signer.generateSignature();

        SigNode = (TElXMLDOMNode) selectedNode;
        if (SigNode instanceof TElXMLDOMDocument)
            SigNode = ((TElXMLDOMDocument) SigNode).getDocumentElement();

        try {
            // If the signature type is enveloping, then the signature is placed into the passed node and the contents of the node are moved to inside of the signature.
            // If the signature type is enveloped, the signature is placed as a child of the passed node.
            TSBObject obj = new TSBObject();
            obj.value = SigNode;
            Signer.save(obj);

            F = new TElFileStream(tempFilePath, "rw", true);
            FXMLDocument.saveToStream(F, SBXMLDefs.xcmNone, "");

            File xmlFile = new File(tempFilePath);
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            dbFactory.setNamespaceAware(true);
            DocumentBuilder dBuilder;
            dBuilder = dbFactory.newDocumentBuilder();
            Document doc = dBuilder.parse(xmlFile);
            doc.getDocumentElement().normalize();

            Node keyValue = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "KeyValue").item(0);
            Node x509IssuerSerial =
                doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "X509IssuerSerial").item(0);
            Node x509SubjectName =
                doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "X509SubjectName").item(0);
            keyValue.getParentNode().removeChild(keyValue);
            x509IssuerSerial.getParentNode().removeChild(x509IssuerSerial);
            x509SubjectName.getParentNode().removeChild(x509SubjectName);

            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty(OutputKeys.METHOD, "xml");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
            DOMSource source = new DOMSource(doc);
            StreamResult streamResult = new StreamResult(new File(outFilePath));
            transformer.transform(source, streamResult);

        } catch (Exception E) {
            E.printStackTrace();
            System.out.println("Signed data saving failed. " + E.getMessage());
            return;
        }

        System.out.println("The file has been succesfully signed");
    }

    protected void sign() {
        byte[] InBuffer, OutBuffer;
        TElFileStream Stream;
        int InSize, res;
        TSBInteger OutSize = new TSBInteger();
        Stream = new TElFileStream(inFilePath, "r", true);
        try {
            InSize = (int) Stream.getLength();
            InBuffer = new byte[InSize];
            Stream.read(InBuffer, 0, InSize);
        } finally {
            Stream.Free();
        }
        OutSize.value = InSize + 16384;
        OutBuffer = new byte[OutSize.value];
        CertStorage.add(Certificate, true);
        Signer.setCertStorage(CertStorage);
        Signer.setUsePSS(false);
        res = Signer.sign(InBuffer, OutBuffer, OutSize, false);
        if (res != 0) {
            System.out.println(String.format("Error {%d} when signing the file", res));
            return;
        }
        Stream = new TElFileStream(outFilePath, "rw", true);
        try {
            Stream.write(OutBuffer, 0, OutSize.value);
        } finally {
            Stream.Free();
        }
        System.out.println("The file has been succesfully signed");
    }

    private void clear() {
        Signer.Free();
        CertStorage.Free();
        Storage.close();
        Storage.Free();
        if (Session != null)
            Session = null;
    }

    public AdvanceSignature() {
        try {
            Properties prop = new Properties();
            String propFileName = "signature.properties";
            propFileName = "D:\\Work\\Signature\\conf\\signature.properties";
            InputStream inputStream = new FileInputStream(propFileName);
            if (inputStream != null) {
                prop.load(inputStream);
                inFilePath = prop.getProperty("inFilePath");
                outFilePath = prop.getProperty("outFilePath");
                tempFilePath = prop.getProperty("tempFilePath");
                dllPath = prop.getProperty("dllPath");
                jniName = prop.getProperty("jniName");
                tokenPass = prop.getProperty("tokenPass");
                licence = prop.getProperty("licence");
            }
        } catch (Exception e) {
            e.printStackTrace();
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            e.printStackTrace(pw);
        }
    }

    public JsonObject SiebelSign(JsonObject input) {
        JsonObject output = new JsonObject();
        String decoded = new String(DatatypeConverter.parseBase64Binary(input.get("xml").getAsString()));
        OutputStream out;
        try {
            out = new FileOutputStream(inFilePath);
            out.write(decoded.getBytes());
            out.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        init();
        load();
        Dsign();
        clear();
        File file = new File(outFilePath);
        try {
            InputStream myScan = new FileInputStream(file);
            byte[] b = new byte[(int) file.length()];
            myScan.read(b);
            String encoded = DatatypeConverter.printBase64Binary(b);
            output.addProperty("signedxml", encoded);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return output;
    }

    public JsonObject SiebelCheck(JsonObject input) {
        JsonObject output = new JsonObject();
        if (checkToken())
            output.addProperty("status", "ok");
        else
            output.addProperty("status", "error");
        return output;
    }
}


