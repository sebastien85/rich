package com.github.textutils.security.xss.model;

import java.util.List;
import java.util.regex.Pattern;

public class Attribute {

	public String 				name;
	public String 				defaultValue;
	public List<Pattern> 		allowedRegExp;
	public RestrictAttribute 	restrictAttribute = RestrictAttribute.NONE;

	@Override
	public String toString() {
		return name;
	}

}
