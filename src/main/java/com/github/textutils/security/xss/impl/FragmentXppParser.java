package com.github.textutils.security.xss.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;

import org.apache.xerces.xni.parser.XMLInputSource;
import org.apache.xerces.xni.parser.XMLParseException;
import org.cyberneko.html.HTMLConfiguration;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/**
 * html片段的Sax模型分析
 * 
 */
public class FragmentXppParser extends HTMLConfiguration {

    protected static final String DOCUMENT_FRAGMENT_PROPERTY = "http://cyberneko.org/html/features/document-fragment";
    protected static final String DEFAULT_ENCODING_PROPERTY  = "http://cyberneko.org/html/properties/default-encoding";
    protected static final String DEFAULT_ENCODING_ALGORITHM = "UTF-8";

    public FragmentXppParser(){
        super();
        this.setFeature(DOCUMENT_FRAGMENT_PROPERTY, true);
        this.setProperty(DEFAULT_ENCODING_PROPERTY, DEFAULT_ENCODING_ALGORITHM);
    }

    public void parse(InputSource source) throws SAXException, IOException {

        try {
            String pubid = source.getPublicId();
            String sysid = source.getSystemId();
            String encoding = source.getEncoding();
            InputStream stream = source.getByteStream();
            Reader reader = source.getCharacterStream();

            XMLInputSource inputSource = new XMLInputSource(pubid, sysid, sysid);
            inputSource.setEncoding(encoding);
            inputSource.setByteStream(stream);
            inputSource.setCharacterStream(reader);

            parse(inputSource);
        } catch (XMLParseException e) {
            Exception ex = e.getException();
            if (ex != null) {
                throw new SAXParseException(e.getMessage(), null, ex);
            }
            throw new SAXParseException(e.getMessage(), null);
        }
    } // end parse(InputSource source, DocumentFragment fragment)

}
