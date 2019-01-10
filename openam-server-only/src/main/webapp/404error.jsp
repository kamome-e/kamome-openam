<%@ page contentType="text/html;charset=UTF-8" language="java" pageEncoding="UTF-8" %>
<%@ page import="java.util.ResourceBundle"%>
<%@ page import="javax.servlet.http.*" %>
<%@ page import="javax.servlet.*" %>
<%@ page import="com.sun.identity.common.SystemConfigurationUtil" %>
<%@ page import="com.sun.identity.shared.Constants" %>
<% request.setCharacterEncoding("utf-8"); %>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
    <head>
        <%
            String deployuri = SystemConfigurationUtil.getProperty(Constants.AM_SERVICES_DEPLOYMENT_DESCRIPTOR);
            ResourceBundle rb = ResourceBundle.getBundle("amConfigurator", request.getLocale());
        %>
        <title>404error</title>
        <link rel="stylesheet" href="<%= deployuri %>/css/new_style.css" type="text/css" charset="UTF-8" />
        <!--[if IE 9]> <link href="<%= deployuri %>/css/ie9.css" rel="stylesheet" type="text/css"> <![endif]-->
        <!--[if lte IE 7]> <link href="<%= deployuri %>/css/ie7.css" rel="stylesheet" type="text/css"> <![endif]-->
    </head>
    <body>
        <div class="container_12">
            <div class="grid_4 suffix_8">
                <a class="logo" href="<%= deployuri %>"></a>
            </div>
            <div class="box box-spaced clear-float">
                <div class="grid_3">
                    <div class="product-logo"></div>
                </div>
                <div class="grid_9">
                    <div class="box-content clear-float">
                        <div class="message">
                            <span class="icon error"></span>
                            <h3>404 Not Found</h3>
                            <p class="message_detail">This is not the web page you are looking for.</p>
                        </div>
                    </div>
                </div>
            </div>
            <div class="footer alt-color">
                <div class="grid_6 suffix_3">
                    <p><% out.print(rb.getString("product.copyrights")); %></p>
                </div>
            </div>
        </div>
    </body>
</html>
