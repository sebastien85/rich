package com.github.textutils.security.xss.impl;

import java.io.StringReader;

import org.apache.batik.css.parser.Parser;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.css.sac.DocumentHandler;
import org.w3c.css.sac.InputSource;

import com.github.textutils.security.xss.ScanException;

public class CssScanner {

    private static final Log logger = LogFactory.getLog(CssScanner.class);

    public String scanStyleSheet(String taintedCss, int sizeLimit, boolean inline) throws ScanException {
        if (taintedCss != null) {
            taintedCss = taintedCss.toLowerCase();
        } else {
            throw new ScanException("taintedCss is null");
        }
        // Parser is not thread safe, DO NOT PUT IT IN CLASS FIELDS VAR DEFINE
        Parser parser = new Parser();
        StringBuilder buffer = new StringBuilder(taintedCss.length() << 1);
        DocumentHandler handler = new CssDocumentHandler(buffer, inline);

        // parse the stylesheet
        parser.setDocumentHandler(handler);
        try {
            // parse the style declaration
            // note this does not count against the size limit because it
            // should already have been counted by the caller since it was
            // embedded in the HTML
            if (inline) {
                parser.parseStyleDeclaration(new InputSource(new StringReader(taintedCss)));
            } else {
                parser.parseStyleSheet(new InputSource(new StringReader(taintedCss)));
            }

        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return buffer.toString();
    }
}
