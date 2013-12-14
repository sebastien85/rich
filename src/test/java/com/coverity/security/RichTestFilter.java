package com.coverity.security;

import java.io.InputStream;

import com.github.textutils.security.xss.Policy;
import com.github.textutils.security.xss.PolicyException;
import com.github.textutils.security.xss.XssXppScanner;

public class RichTestFilter {

    public static void main(String[] args) throws PolicyException {
        InputStream inputStream = XssXppScanner.class.getClassLoader().getResourceAsStream("com/github/textutils/security/xss/resources/tt-xss.xml");
        System.out.println(inputStream);
        Policy p = Policy.getCustomerPolicyInstance(inputStream);
        XssXppScanner scanner  = new XssXppScanner(p);
        
        String txt = scanner.scan("<title><img/src=1 onerror=alert(1)//\"><img a=\"onerror=alert(1)//\"><p><img src=\"/p2pserver/bid/imgs/bidimg_30_3298559209792624904.jpg\" style=\"float:none;\" title=\"back.jpg\"/></p><p><img src=\"/p2pserver/bid/imgs/bidimg_30_492533416040017502.jpg\" style=\"float:none;\" title=\"front.jpg\"/></p><p><br/></p>");
        System.out.println(txt);
        
    }
}
