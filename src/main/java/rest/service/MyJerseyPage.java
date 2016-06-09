package rest.service;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import javax.ws.rs.Consumes;
import javax.ws.rs.CookieParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.inpher.clientapi.FrontendPath;
import org.inpher.clientapi.InpherClient;
import org.inpher.clientapi.InpherUser;
import org.inpher.clientapi.RankedSearchResult;
import org.inpher.clientapi.SearchResponse;
import org.inpher.clientapi.efs.BackendIterator;
import org.inpher.clientapi.efs.Element;
import org.inpher.clientapi.efs.SearchableFileSystem;
import org.inpher.clientapi.efs.exceptions.ParentNotFoundException;
import org.inpher.clientapi.efs.exceptions.PathIsDirectoryException;
import org.inpher.clientapi.efs.exceptions.PathNotFoundException;
import org.inpher.clientapi.exceptions.AuthenticationException;
import org.inpher.clientapi.exceptions.ElementAlreadySharedException;
import org.inpher.clientapi.exceptions.ExistingMemberException;
import org.inpher.clientapi.exceptions.ExistingUserException;
import org.inpher.clientapi.exceptions.InpherException;
import org.inpher.clientapi.exceptions.InpherRuntimeException;
import org.inpher.clientapi.exceptions.NonEmptyDirectoryException;
import org.inpher.clientapi.exceptions.PathNotOwnedByUserException;
import org.json.JSONObject;
import org.json.simple.JSONArray;

import com.sun.jersey.core.header.FormDataContentDisposition;
import com.sun.jersey.multipart.FormDataParam;

@Path("/")
public class MyJerseyPage {
	private static InpherClient inpherClient;
	private static Map<String, SearchableFileSystem> sfss;
	private static String AUTH_TOKEN = "auth_token";

	static {
		Security.addProvider(new BouncyCastleProvider());
		sfss = new ConcurrentHashMap<String, SearchableFileSystem>();
		try {
			inpherClient = InpherClient.getClient("D:\\workspace\\rest.service\\src\\config.properties");
		} catch (InpherException e) {
			e.printStackTrace();
		}
	}

	@GET
	@Produces(MediaType.TEXT_HTML)
	public String sayHtmlHello() {
		return "Hello from Jersey";
	}

	@Path("register")
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	public Response register(User user) {
		if (user.getName() == null || user.getPassword() == null) {
			return Response.status(400).entity("password and name should not be empty").build();
		}
		try {
			inpherClient.registerUser(new InpherUser(user.getName(), user.getPassword()));
		} catch (ExistingUserException e) {
			return Response.status(409).entity("user already exists").build();
		}
		return Response.ok().build();
	}

	@Path("login")
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	public Response login(User user) {
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
	public Response mkdir(String dir, @CookieParam("auth_token") Cookie cookie) {
		SearchableFileSystem sfs = sfss.get(cookie.getValue());
		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		try {
			sfs.mkdir(FrontendPath.parse(dir));
		} catch (ParentNotFoundException e) {
			return Response.status(400).entity("The parent of the dir does not exist.").build();
		} catch (InpherRuntimeException e) {
			return Response.status(400).entity("An error occured. Please check: " + e.getMessage()).build();
		}

		String result = "Dir created successfully : " + dir;
		return Response.status(201).entity(result).build();
	}

	@Path("listDir")
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response listDir(String dir, @CookieParam("auth_token") Cookie cookie) {
		SearchableFileSystem sfs = sfss.get(cookie.getValue());
		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		JSONArray arr = new JSONArray();
		try {
			BackendIterator<Element> iterator = sfs.list(FrontendPath.parse(dir));
			while (iterator.hasNext()) {
				Element el = iterator.next();
				arr.add(el);
			}
		} catch (InpherRuntimeException e) {
			return Response.status(400).entity("An error occured. Please check: " + e.getMessage()).build();
		} catch (PathNotFoundException e) {
			return Response.status(400).entity("The dir does not exist.").build();
		}
		return Response.ok(arr).build();
	}

	@Path("upload")
	@POST
	@Consumes(MediaType.MULTIPART_FORM_DATA)
	public Response uploadFile(@FormDataParam("content") final InputStream content,
			@FormDataParam("content") FormDataContentDisposition contentDispositionHeader,
			@FormDataParam("name") String name, @CookieParam("auth_token") Cookie cookie) {
		SearchableFileSystem sfs = sfss.get(cookie.getValue());

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		File file = new File("temp.tmp");
		try {
			FileUtils.copyInputStreamToFile(content, file);
		} catch (IOException e) {
			return Response.status(400).entity("An error occured. Please check: " + e.getMessage()).build();
		}
		try {
			sfs.upload(file, FrontendPath.parse(name));
		} catch (ParentNotFoundException e) {
			return Response.status(400).entity("The parent of the dir does not exists.").build();
		} catch (InpherRuntimeException e) {
			return Response.status(400).entity("An error occured. Please check: " + e.getMessage()).build();
		}
		return Response.ok("file uploaded").build();
	}

	@Path("download")
	@GET
	@Produces("text/plain")
	public Response downloadFile(@QueryParam("fileName") String fileName, @CookieParam("auth_token") Cookie cookie) {
		if (cookie == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfss.get(cookie.getValue());

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		File file = new File("temp.tmp");
		FrontendPath filePath = FrontendPath.parse(fileName);
		try {
			sfs.download(filePath, file);
		} catch (PathNotFoundException e) {
			return Response.status(400).entity("The file does not exist.").build();
		} catch (PathIsDirectoryException e) {
			return Response.status(400).entity("The path points to a directory").build();
		} catch (InpherRuntimeException e) {
			return Response.status(400).entity("An error occured. Please check: " + e.getMessage()).build();
		}
		ResponseBuilder response = Response.ok((Object) file);
		response.header("Content-Disposition", "attachment; filename=\"" + filePath.getLastElementName() + "\"");
		return response.build();
	}

	@Path("delete")
	@GET
	public Response delete(@QueryParam("fileName") String fileName, @QueryParam("recursive") boolean recursive,
			@CookieParam("auth_token") Cookie cookie) {
		if (cookie == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfss.get(cookie.getValue());

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		try {
			sfs.delete(FrontendPath.parse(fileName), recursive);
		} catch (NonEmptyDirectoryException e) {
			return Response.status(400).entity("The path points to a directory that is not emptry").build();
		} catch (PathNotOwnedByUserException e) {
			return Response.status(400).entity("You cannot delete the resource. The path does not belong to you")
					.build();
		} catch (PathNotFoundException e) {
			return Response.status(400).entity("The resource does not exist.").build();
		} catch (InpherRuntimeException e) {
			return Response.status(400).entity("An error occured. Please check: " + e.getMessage()).build();
		}
		return Response.ok("resource deleted").build();
	}

	@Path("search")
	@GET
	public Response search(@QueryParam("keywords") String keywords, @CookieParam("auth_token") Cookie cookie) {
		if (cookie == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfss.get(cookie.getValue());

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		String[] words = keywords.split(" ");
		SearchResponse results = sfs.search(Arrays.asList(words));
		JSONArray arr = new JSONArray();
		for (RankedSearchResult el : results.getAllRankedSearchResults()) {
			arr.add(el);
		}

		JSONObject ret = new JSONObject();
		ret.put("totalHits", results.getTotalHits());
		ret.put("results", arr);
		return Response.ok(ret.toString()).build();
	}

	@Path("path")
	@GET
	public Response exists(@QueryParam("path") String path, @CookieParam("auth_token") Cookie cookie) {
		if (cookie == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfss.get(cookie.getValue());

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		boolean exists = sfs.exists(FrontendPath.parse(path));
		return Response.ok(exists).build();
	}

	@Path("isMember")
	@GET
	public Response isMember(@QueryParam("groupName") String groupName, @QueryParam("userName") String userName,
			@CookieParam("auth_token") Cookie cookie) {
		if (cookie == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfss.get(cookie.getValue());

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		boolean isMember = sfs.isMember(groupName, userName);
		return Response.ok(isMember).build();
	}

	@Path("owner")
	@GET
	public Response owner(@QueryParam("fileName") String fileName, @CookieParam("auth_token") Cookie cookie) {
		if (cookie == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfss.get(cookie.getValue());

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		String owner;
		try {
			owner = sfs.elementOwner(FrontendPath.parse(fileName));
		} catch (PathNotFoundException e) {
			return Response.status(400).entity("The resource does not exist.").build();
		} catch (InpherRuntimeException e) {
			return Response.status(400).entity("An error occured. Please check: " + e.getMessage()).build();
		}
		return Response.ok(owner).build();
	}

	@Path("addUser")
	@GET
	public Response addUser(@QueryParam("groupName") String groupName, @QueryParam("userName") String userName,
			@CookieParam("auth_token") Cookie cookie) {
		if (cookie == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfss.get(cookie.getValue());

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		try {
			sfs.addUser(groupName, userName);
		} catch (ExistingMemberException e) {
			return Response.status(400).entity("The user is already a part of the group.").build();
		}
		return Response.ok("user added").build();
	}

	@Path("revokeUser")
	@GET
	public Response revokeUser(@QueryParam("groupName") String groupName, @QueryParam("userName") String userName,
			@CookieParam("auth_token") Cookie cookie) {
		if (cookie == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfss.get(cookie.getValue());

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		sfs.revokeUser(groupName, userName);
		return Response.ok("user revoked").build();
	}

	@Path("shareElement")
	@GET
	public Response shareElement(@QueryParam("groupName") String groupName, @QueryParam("filePath") String filePath,
			@QueryParam("shareName") String shareName, @CookieParam("auth_token") Cookie cookie) {
		if (cookie == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfss.get(cookie.getValue());

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		try {
			sfs.shareElement(groupName, FrontendPath.parse(filePath), shareName);
		} catch (ElementAlreadySharedException e) {
			return Response.status(400).entity("The element is already shared.").build();
		} catch (PathNotOwnedByUserException e) {
			return Response.status(400).entity("You can share only your own resources.").build();
		} catch (PathNotFoundException e) {
			return Response.status(400).entity("The resource does not exist.").build();
		} catch (InpherRuntimeException e) {
			return Response.status(400).entity("An error occured. Please check: " + e.getMessage()).build();
		}
		return Response.ok("element shared").build();
	}

	@Path("unshareElement")
	@GET
	public Response unshareElement(@QueryParam("groupName") String groupName, @QueryParam("shareName") String shareName,
			@CookieParam("auth_token") Cookie cookie) {
		if (cookie == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfss.get(cookie.getValue());

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		try {
			sfs.unshareElement(groupName, shareName);
		} catch (ElementAlreadySharedException e) {
			return Response.status(400).entity("The element is already shared.").build();
		} catch (PathNotOwnedByUserException e) {
			return Response.status(400).entity("You can share only your own resources.").build();
		} catch (PathNotFoundException e) {
			return Response.status(400).entity("The resource does not exist.").build();
		} catch (InpherRuntimeException e) {
			return Response.status(400).entity("An error occured. Please check: " + e.getMessage()).build();
		}
		return Response.ok("element shared").build();
	}
}
