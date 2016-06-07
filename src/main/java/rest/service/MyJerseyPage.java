package rest.service;

import java.io.File;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import javax.ws.rs.Consumes;
import javax.ws.rs.CookieParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;

import org.inpher.clientapi.FrontendPath;
import org.inpher.clientapi.InpherClient;
import org.inpher.clientapi.InpherUser;
import org.inpher.clientapi.efs.BackendIterator;
import org.inpher.clientapi.efs.Element;
import org.inpher.clientapi.efs.SearchableFileSystem;
import org.inpher.clientapi.efs.exceptions.ParentNotFoundException;
import org.inpher.clientapi.efs.exceptions.PathNotFoundException;
import org.inpher.clientapi.exceptions.AuthenticationException;
import org.inpher.clientapi.exceptions.ExistingUserException;
import org.inpher.clientapi.exceptions.InpherException;
import org.inpher.clientapi.exceptions.InpherRuntimeException;
import org.json.JSONObject;
import org.json.simple.JSONArray;

@Path("/")
public class MyJerseyPage {
	private static InpherClient inpherClient;
	private static Map<String, SearchableFileSystem> sfss;
	private static String AUTH_TOKEN = "auth_token";
	
	@GET
	@Produces(MediaType.TEXT_HTML)
	public String sayHtmlHello() {
		return "Hello from Jersey";
	}
	static {
		sfss = new ConcurrentHashMap<String, SearchableFileSystem>();
		try {
			inpherClient = InpherClient.getClient("D:\\workspace\\rest.service\\src\\config.properties");
		} catch (InpherException e) {
			e.printStackTrace();
		}
	}
	
	@Path("hi")
	@POST
	@Produces(MediaType.TEXT_HTML)
	public String hi() {
		return "Hello from Jersey";
	}
	
	@Path("register")
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	public Response register(User user){
		if (user.getName() == null || user.getPassword() == null) {
            return Response.status(400).entity("password and name should not be empty").build();
        }
        try {
            inpherClient.registerUser(
                    new InpherUser(user.getName(), user.getPassword()));
        } catch (ExistingUserException e) {
            return Response.status(409).entity("user already exists").build();
        }
        return Response.status(200).entity("success").build();
	}
	
	@Path("login")
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	public Response login(User user){
		SearchableFileSystem sfs;
        try {
            sfs = inpherClient.loginUser(new InpherUser(user.getName(), user.getPassword()));
        } catch (AuthenticationException e) {
            return Response.status(409).entity("Authentication failed").build();
        }
		
		String result = "Person logged in successfully : " + user.getName();
	    String token = UUID.randomUUID().toString();
		NewCookie cookie = new NewCookie(AUTH_TOKEN, token);
		sfss.put(token, sfs);
		return Response.status(201).entity(result).cookie(cookie).build();
	}
	
	@Path("mkdir")
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	public Response mkdir(String dir, @CookieParam("auth_token") Cookie cookie){
		SearchableFileSystem sfs = sfss.get(cookie.getValue());
        if(sfs == null){
            return Response.status(409).entity("Authentication failed").build();
        }
		try {
			sfs.mkdir(FrontendPath.parse(dir));
		} catch (ParentNotFoundException e) {
            return Response.status(400).entity("The parent of the dir does not exists.").build();
		} catch (InpherRuntimeException e) {
            return Response.status(400).entity("An error occured. Please check: " + e.getMessage())
            		.build();
		}

		String result = "Dir created successfully : " + dir;
		return Response.status(201).entity(result).build();
	}
	
	@Path("listDir")
	@POST
	@Consumes(MediaType.APPLICATION_JSON)	
	@Produces(MediaType.APPLICATION_JSON)
	public Response listDir(String dir, @CookieParam("auth_token") Cookie cookie){
		SearchableFileSystem sfs = sfss.get(cookie.getValue());
        if(sfs == null){
            return Response.status(409).entity("Authentication failed").build();
        }
        JSONArray arr = new JSONArray();
		try {
			BackendIterator<Element> iterator = sfs.list(FrontendPath.parse(dir));
			while(iterator.hasNext()){
				Element el = iterator.next();
				arr.add(el);
			}
		} catch (InpherRuntimeException e) {
            return Response.status(400).entity("An error occured. Please check: " + e.getMessage())
            		.build();
		} catch (PathNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return Response.ok(arr).build();
	}
}


