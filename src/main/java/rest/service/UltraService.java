package rest.service;

import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.glassfish.jersey.media.multipart.FormDataContentDisposition;
import org.glassfish.jersey.media.multipart.FormDataParam;
import org.inpher.clientapi.*;
import org.inpher.clientapi.crypto.Certificate;
import org.inpher.clientapi.efs.BackendIterator;
import org.inpher.clientapi.efs.Element;
import org.inpher.clientapi.efs.SearchableFileSystem;
import org.inpher.clientapi.efs.exceptions.ParentNotFoundException;
import org.inpher.clientapi.efs.exceptions.PathAlreadyExistsException;
import org.inpher.clientapi.efs.exceptions.PathIsDirectoryException;
import org.inpher.clientapi.efs.exceptions.PathNotFoundException;
import org.inpher.clientapi.exceptions.*;

import javax.ws.rs.*;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Path("/")
public class UltraService {
	private static InpherClient inpherClient;
	private static Map<String, String> tokenToUserNameMap;
	private static Map<String, Set<String>> userNameToTokensMap;
	private static Map<String, SearchableFileSystem> userNameToSFSMap;
	private static Map<String, SaltAndHash> userNameToPasswordMap;
	private static SecureRandom random;
	static Logger log = Logger.getLogger(UltraService.class.getName());

	static {
		// Security.addProvider(new BouncyCastleProvider());
		userNameToSFSMap = new ConcurrentHashMap<>();
		tokenToUserNameMap = new ConcurrentHashMap<>();
		userNameToPasswordMap = new ConcurrentHashMap<>();
		userNameToTokensMap = new ConcurrentHashMap<>();
		random = new SecureRandom();
		try {
			// inpherClient = InpherClient.getClient();
			URL config = UltraService.class.getResource("/config.properties");
			if (config != null) {
				System.err.println("Using " + config.getFile());
				inpherClient = InpherClient.getClient(config.getFile());
			} else {
				log.error("No config properties found");
				System.err.println("No config properties found");
			}
		} catch (Exception e) {
			log.error(e.getMessage(), e);
		}
	}

	@GET
	@Produces(MediaType.TEXT_HTML)
	public String sayHtmlHello() {
		return "Hello from _ultra rest API";
	}

	@Path("testJSON")
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response sayJsonHello(User user) {
		HashMap<String, Object> reps = new HashMap<>();
		reps.put("user", user);
		reps.put("message", "Hello from _ultra rest API");
		return Response.ok(reps).build();
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
			log.error(e.getMessage(), e);
			return Response.status(400).entity("user already exists").build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
		return Response.ok().build();
	}

	@Path("register")
	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response register(@FormParam("username") String username, @FormParam("password") String password) {
		if (username == null || password == null) {
			return Response.status(400).entity("Password and name should not be empty.").build();
		}
		try {
			inpherClient.registerUser(new InpherUser(username, password));
		} catch (ExistingUserException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("User already exists.").build();
		} catch (IllegalArgumentException e) {
			log.error(e.getMessage(), e);
			return Response.status(400)
					.entity("Invalid user name. It should not be empty and can contain only alphanumerical characters, underscores, and dashes")
					.build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
		return Response.ok().build();
	}

	private synchronized Response privLogin(String username, String password) {
		if (username == null || password == null)
			return Response.status(409).entity("Authentication failed").build();
		SearchableFileSystem sfs;
		try {
			if (userNameToSFSMap.containsKey(username)) {// already logged in
				if (!verifyHash(userNameToPasswordMap.get(username), password)) // password
																				// incorrect
					throw new AuthenticationException(username);
			} else { // First login: do the proper login
				sfs = inpherClient.loginUser(new InpherUser(username, password));
				userNameToSFSMap.put(username, sfs);
				userNameToPasswordMap.put(username, createHash(password));
			}
		} catch (AuthenticationException e) {
			log.error(e.getMessage(), e);
			return Response.status(409).entity("Authentication failed").build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}

		// String result = "Person logged in successfully : " + username;
		String token = UUID.randomUUID().toString();
		// NewCookie authToken = new NewCookie(AUTH_TOKEN, token);
		tokenToUserNameMap.put(token, username);
		MultiMaps.multimapInsert(userNameToTokensMap, username, token);
		HashMap<String, Object> reps = new HashMap<>();
		reps.put("auth_token", token);
		reps.put("username", username);
		return Response.status(200).entity(reps).build();
	}

	@Path("login")
	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Produces(MediaType.APPLICATION_JSON)
	public Response login(@FormParam("username") String username, @FormParam("password") String password) {
		return privLogin(username, password);
	}

	@Path("login")
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response login(User user) {
		return privLogin(user.getName(), user.getPassword());
	}

	@Path("logout")
	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public synchronized Response logout(@HeaderParam("auth_token") String authToken) {
		if (authToken == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		try {
			SearchableFileSystem sfs = sfsFromToken(authToken);
			if (sfs == null) {
				return Response.status(409).entity("Authentication failed").build();
			}
			String username = tokenToUserNameMap.get(authToken);
			tokenToUserNameMap.remove(authToken);
			MultiMaps.multimapRemove(userNameToTokensMap, username, authToken);
			// if all tokens are logged out, we can safely delete the sfs
			if (MultiMaps.multimapIsKeyEmpty(userNameToTokensMap, username)) {
				userNameToSFSMap.remove(username);
				inpherClient.logoutUser(sfs);
			}
			return Response.status(200).entity("logged out").build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
	}

	@Path("userCertificate")
	@GET
	@Produces(MediaType.TEXT_PLAIN)
	public Response userCertificate(@QueryParam("username") String username,
			@HeaderParam("auth_token") String authToken) {
		if (authToken == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfsFromToken(authToken);
		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		if (username == null)
			return Response.status(400).entity("Username cannot be empty").build();
		try {
			Certificate cert = inpherClient.getUserCertificate(username);
			return Response.status(200).entity(cert.toString()).build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
	}

	@Path("doesSharingGroupExists")
	@GET
	public Response doesSharingGroupExists(@QueryParam("groupName") String groupName,
			@HeaderParam("auth_token") String authToken) {
		if (authToken == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfsFromToken(authToken);
		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		try {
			Boolean exists = inpherClient.doesSharingGroupExists(groupName);
			return Response.status(200).entity(exists.toString()).build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
	}

	@Path("createSharingGroup")
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	public Response createSharingGroup(GroupRequest groupRequest, @HeaderParam("auth_token") String authToken) {
		if (authToken == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfsFromToken(authToken);
		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		try {
			inpherClient.createSharingGroup(sfs, groupRequest.getGroupName(), groupRequest.getUsernames());
			return Response.status(201).entity("Sharing group successfully created.").build();
		} catch (IllegalArgumentException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("Illegal arguments: one user might not exist").build();
		} catch (ExistingSharingGroupException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("Sharing group name already exists.").build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
	}

	@Path("mkdir")
	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response mkdir(@FormParam("dir") String dir, @HeaderParam("auth_token") String authToken) {
		if (authToken == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfsFromToken(authToken);
		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		try {
			sfs.mkdir(FrontendPath.parse(dir));
		} catch (ParentNotFoundException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("The parent of the dir does not exist.").build();
		} catch (InpherRuntimeException | IllegalArgumentException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("An error occurred. Please check: " + e.getMessage()).build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
		if (dir == null || dir.trim().equals("")) {
			return Response.status(400).entity("Name of directory cannot be empty").build();
		}

		String result = "Dir created successfully : " + dir;
		return Response.status(201).entity(result).build();
	}

	@Path("listDir")
	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public Response listDir(@QueryParam("dir") String dir, @HeaderParam("auth_token") String authToken) {
		if (authToken == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfsFromToken(authToken);
		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		ArrayList<Map<String, Object>> arr = new ArrayList<>();
		try {
			BackendIterator<Element> iterator = sfs.list(FrontendPath.parse(dir));
			while (iterator.hasNext()) {
				Element el = iterator.next();
				Map<String, Object> elJS = elementToJSObject(el);
				elJS.put("groups", sfs.getAuthorizedGroups(el.getFrontendPath()).stream().collect(Collectors.toList()));
				arr.add(elJS);
			}
		} catch (InpherRuntimeException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("An error occurred. Please check: " + e.getMessage()).build();
		} catch (PathNotFoundException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("The dir does not exist.").build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
		HashMap<String, Object> ret = new HashMap<>();
		ret.put("list", arr);
		return Response.ok(ret).build();
	}

	@Path("listDirPaged")
	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public Response listDirPaged(@QueryParam("dir") String dir, @QueryParam("page") int page,
			@QueryParam("num") int num, @HeaderParam("auth_token") String authToken) {
		if (authToken == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfsFromToken(authToken);
		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		ArrayList<Map<String, Object>> arr = new ArrayList<>();
		try {
			BackendIterator<Element> iterator = sfs.list(FrontendPath.parse(dir));
			int i = 0;
			while (iterator.hasNext()) {
				i++;
				Element el = iterator.next();
				if (i >= page * num && i < ((page * num) + num)) {
					Map<String, Object> elJS = elementToJSObject(el);
					elJS.put("groups",
							sfs.getAuthorizedGroups(el.getFrontendPath()).stream().collect(Collectors.toList()));
					arr.add(elJS);
				}
			}
		} catch (InpherRuntimeException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("An error occurred. Please check: " + e.getMessage()).build();
		} catch (PathNotFoundException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("The dir does not exist.").build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
		HashMap<String, Object> ret = new HashMap<>();
		ret.put("list", arr);
		return Response.ok(ret).build();
	}

	private Map<String, Object> elementToJSObject(Element el) {
		Map<String, Object> elMap = new HashMap<>();
		elMap.put("path", el.getFrontendURI());
		elMap.put("type", el.getType().name());
		elMap.put("size", "" + el.getSize());
		return elMap;
	}

	@Path("upload")
	@POST
	@Consumes(MediaType.MULTIPART_FORM_DATA)
	public Response uploadFile(@FormDataParam("content") final InputStream content,
			@FormDataParam("content") FormDataContentDisposition contentDispositionHeader,
			@FormDataParam("name") String name, @HeaderParam("auth_token") String authToken) {
		if (authToken == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfsFromToken(authToken);

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}

		File file = null;
		try {
			file = File.createTempFile("inpherUpload", "tmp");
			FileUtils.copyInputStreamToFile(content, file);
		} catch (IOException e) {
			return Response.status(400).entity("An error occurred. Please check: " + e.getMessage()).build();
		}
		try {
			sfs.upload(file, FrontendPath.parse(name));
		} catch (ParentNotFoundException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("The parent of the dir does not exists.").build();
		} catch (InpherRuntimeException | IllegalArgumentException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("An error occurred. Please check: " + e.getMessage()).build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
		file.delete();
		return Response.ok("file uploaded").build();
	}

	@Path("download")
	@GET
	@Produces("text/plain")
	public Response downloadFile(@QueryParam("fileName") String fileName, @HeaderParam("auth_token") String authToken) {
		if (authToken == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfsFromToken(authToken);

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		try {
			File file = File.createTempFile("download", ".tmp");
			FrontendPath filePath = FrontendPath.parse(fileName);
			try {
				sfs.download(filePath, file);
			} catch (PathNotFoundException e) {
				log.error(e.getMessage(), e);
				return Response.status(400).entity("The file does not exist.").build();
			} catch (PathIsDirectoryException e) {
				log.error(e.getMessage(), e);
				return Response.status(400).entity("The path points to a directory").build();
			} catch (InpherRuntimeException e) {
				log.error(e.getMessage(), e);
				return Response.status(400).entity("An error occurred. Please check: " + e.getMessage()).build();
			}
			ResponseBuilder response = Response.ok(new AutoDeleteFileInputStream(file));
			response.header(HttpHeaders.CONTENT_DISPOSITION,
					"attachment; filename=\"" + filePath.getLastElementName() + "\"");
			response.header(HttpHeaders.CONTENT_LENGTH, file.length());
			return response.build();
		} catch (IOException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("Impossible to create temporary file.").build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
	}

	@Path("delete")
	@DELETE
	public Response delete(@QueryParam("path") String path, @QueryParam("recursive") boolean recursive,
			@HeaderParam("auth_token") String authToken) {
		if (authToken == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfsFromToken(authToken);

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		try {
			sfs.delete(FrontendPath.parse(path), recursive);
		} catch (NonEmptyDirectoryException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("The path points to a directory that is not empty").build();
		} catch (PathNotOwnedByUserException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("You cannot delete the resource. The path does not belong to you")
					.build();
		} catch (PathNotFoundException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("The resource does not exist.").build();
		} catch (InpherRuntimeException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("An error occurred. Please check: " + e.getMessage()).build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
		return Response.ok("resource deleted").build();
	}

	@Path("move")
	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response move(@FormParam("oldPath") String oldPath, @FormParam("newPath") String newPath,
			@HeaderParam("auth_token") String authToken) {
		if (authToken == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfsFromToken(authToken);

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		try {
			sfs.move(FrontendPath.parse(oldPath), FrontendPath.parse(newPath));
		} catch (PathNotFoundException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("The resource does not exist.").build();
		} catch (PathAlreadyExistsException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("The new path is already in use.").build();
		} catch (InpherRuntimeException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("An error occurred. Please check: " + e.getMessage()).build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
		return Response.ok("resource moved").build();
	}

	@Path("search")
	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Produces(MediaType.APPLICATION_JSON)
	public Response search(@FormParam("query") String query, @HeaderParam("auth_token") String authToken) {
		if (authToken == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfsFromToken(authToken);

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		if (query == null) {
			return Response.status(400).entity("Empty query").build();
		}
		try {
			SearchResponse results = sfs.search(query);
			ArrayList<HashMap<String, Object>> arr = new ArrayList<>();
			for (RankedSearchResult el : results.getAllRankedSearchResults()) {
				HashMap<String, Object> rankedResult = new HashMap<>();
				rankedResult.put("score", el.getScore());
				rankedResult.put("path", el.getPath().toString());
				arr.add(rankedResult);
			}

			HashMap<String, Object> ret = new HashMap<>();
			ret.put("totalHits", results.getTotalHits());
			ret.put("results", arr);
			return Response.ok(ret).build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
	}

	@Path("searchPaged")
	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Produces(MediaType.APPLICATION_JSON)
	public Response search(@FormParam("query") String query, @FormParam("page") int page,
			@FormParam("numRes") int numRes, @HeaderParam("auth_token") String authToken) {
		if (authToken == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfsFromToken(authToken);

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		if (query == null) {
			return Response.status(400).entity("Empty query").build();
		}
		try {
			SearchResponse results = sfs.search(query, page, numRes);
			ArrayList<RankedSearchResult> arr = new ArrayList<>();
			arr.addAll(results.getAllRankedSearchResults());

			HashMap<String, Object> ret = new HashMap<>();
			ret.put("totalHits", results.getTotalHits());
			ret.put("results", arr);
			return Response.ok(ret.toString()).build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
	}

	@Path("isFile")
	@GET
	public Response isFile(@QueryParam("path") String path, @HeaderParam("auth_token") String authToken) {
		if (authToken == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfsFromToken(authToken);

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		try {
			Boolean isFile = sfs.isFile(FrontendPath.parse(path));
			return Response.ok(isFile.toString()).build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
	}

	@Path("isDirectory")
	@GET
	public Response isDirectory(@QueryParam("path") String path, @HeaderParam("auth_token") String authToken) {
		if (authToken == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfsFromToken(authToken);

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		try {
			Boolean isDirectory = sfs.isDirectory(FrontendPath.parse(path));
			return Response.ok(isDirectory.toString()).build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
	}

	@Path("exists")
	@GET
	public Response exists(@QueryParam("path") String path, @HeaderParam("auth_token") String authToken) {
		if (authToken == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfsFromToken(authToken);

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		try {
			Boolean exists = sfs.exists(FrontendPath.parse(path));
			return Response.ok(exists.toString()).build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
	}

	@Path("listGroups")
	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public Response listGroups(@HeaderParam("auth_token") String authToken) {
		if (authToken == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfsFromToken(authToken);

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		try {
			Collection<String> groups = sfs.listGroups();
			ArrayList<String> arr = new ArrayList<>();
			for (String group : groups) {
				arr.add(group);
			}
			return Response.ok(arr).build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
	}

	@Path("listAuthorizedGroups")
	@GET
	public Response listAuthorizedGroups(@QueryParam("path") String path, @HeaderParam("auth_token") String authToken) {
		if (authToken == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfsFromToken(authToken);

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		Collection<String> groups = null;
		try {
			groups = sfs.getAuthorizedGroups(FrontendPath.parse(path));
		} catch (PathNotFoundException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("The resource does not exist.").build();
		} catch (InpherRuntimeException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("An error occurred. Please check: " + e.getMessage()).build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
		ArrayList<String> arr = new ArrayList<>();
		for (String group : groups) {
			arr.add(group);
		}
		return Response.ok(arr).build();
	}

	@Path("isMember")
	@GET
	public Response isMember(@QueryParam("groupName") String groupName, @QueryParam("userName") String userName,
			@HeaderParam("auth_token") String authToken) {
		if (authToken == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfsFromToken(authToken);

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		try {
			Boolean isMember = sfs.isMember(groupName, userName);
			return Response.ok(isMember.toString()).build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
	}

	@Path("owner")
	@GET
	public Response owner(@QueryParam("fileName") String fileName, @HeaderParam("auth_token") String authToken) {
		if (authToken == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfsFromToken(authToken);

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		if (fileName == null) {
			return Response.status(400).entity("File name cannot be empty").build();
		}
		String owner;
		try {
			owner = sfs.elementOwner(FrontendPath.parse(fileName));
		} catch (PathNotFoundException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("The resource does not exist.").build();
		} catch (InpherRuntimeException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("An error occurred. Please check: " + e.getMessage()).build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
		return Response.ok(owner).build();
	}

	@Path("addUser")
	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response addUser(@FormParam("groupName") String groupName, @FormParam("userName") String userName,
			@HeaderParam("auth_token") String authToken) {
		if (authToken == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfsFromToken(authToken);

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		try {
			sfs.addUser(groupName, userName);
		} catch (ExistingMemberException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("The user is already a part of the group.").build();
		} catch (NonExistingGroupException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("This group does not exist.").build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
		return Response.ok("user added").build();
	}

	@Path("revokeUser")
	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response revokeUser(@FormParam("groupName") String groupName, @FormParam("userName") String userName,
			@HeaderParam("auth_token") String authToken) {
		if (authToken == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfsFromToken(authToken);

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		try {
			sfs.revokeUser(groupName, userName);
			return Response.ok("user revoked").build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
	}

	@Path("shareElement")
	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response shareElement(@FormParam("groupName") String groupName, @FormParam("filePath") String filePath,
			@FormParam("shareName") String shareName, @HeaderParam("auth_token") String authToken) {
		if (authToken == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfsFromToken(authToken);

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		try {
			sfs.shareElement(groupName, FrontendPath.parse(filePath), shareName);
		} catch (ElementAlreadySharedException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("The element is already shared.").build();
		} catch (PathNotOwnedByUserException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("You can only share your own resources.").build();
		} catch (PathNotFoundException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("The resource does not exist.").build();
		} catch (InpherRuntimeException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("An error occurred. Please check: " + e.getMessage()).build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
		return Response.ok("element shared").build();
	}

	@Path("unshareElement")
	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response unshareElement(@FormParam("groupName") String groupName, @FormParam("shareName") String shareName,
			@HeaderParam("auth_token") String authToken) {
		if (authToken == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfsFromToken(authToken);

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		try {
			sfs.unshareElement(groupName, shareName);
		} catch (PathNotOwnedByUserException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("You can unshare only your own resources.").build();
		} catch (PathNotFoundException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("The resource does not exist.").build();
		} catch (InpherRuntimeException e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("An error occurred. Please check: " + e.getMessage()).build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
		return Response.ok("element unshared").build();
	}

	@Path("refreshGroupKeyring")
	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public Response refreshGroupKeyring(@FormParam("groupName") String groupName,
			@HeaderParam("auth_token") String authToken) {
		if (authToken == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfsFromToken(authToken);

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		try {
			sfs.refreshGroupKeyring(groupName);
			return Response.ok("group keyring is refreshed").build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
	}

	@Path("refreshUserKeyring")
	@POST
	public Response refreshUserKeyring(@FormParam("password") String password,
			@HeaderParam("auth_token") String authToken) {
		if (authToken == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		SearchableFileSystem sfs = sfsFromToken(authToken);

		if (sfs == null) {
			return Response.status(409).entity("Authentication failed").build();
		}
		try {
			sfs.refreshUserKeyring(password);
		} catch (AuthenticationException e) {
			log.error(e.getMessage(), e);
			return Response.status(409).entity("Authentication failed").build();
		} catch (Exception e) {
			log.error(e.getMessage(), e);
			return Response.status(400).entity("A problem occurred, please try again later.").build();
		}
		return Response.ok("user keyring is refreshed").build();
	}

	private static SaltAndHash createHash(String password) {
		byte[] salt = new byte[16];
		random.nextBytes(salt);
		byte[] out = hashSaltAndPassword(salt, password);
		return new SaltAndHash(Base64.getEncoder().encodeToString(salt), Base64.getEncoder().encodeToString(out));
	}

	private static boolean verifyHash(SaltAndHash saltAndHash, String password) {
		byte[] salt = Base64.getDecoder().decode(saltAndHash.salt);
		byte[] hash = Base64.getDecoder().decode(saltAndHash.hash);
		return (Arrays.equals(hash, hashSaltAndPassword(salt, password)));
	}

	private static byte[] hashSaltAndPassword(byte[] salt, String password) {
		byte[] message = password.getBytes(StandardCharsets.UTF_8);
		SHA256Digest digest = new SHA256Digest();
		digest.update(salt, 0, salt.length);
		digest.update(message, 0, message.length);
		byte[] out = new byte[digest.getDigestSize()];
		digest.doFinal(out, 0);
		return out;
	}

	private static SearchableFileSystem sfsFromToken(String token) {
		String username;
		if (token != null && (username = tokenToUserNameMap.get(token)) != null)
			return userNameToSFSMap.get(username);
		else
			return null;
	}

	private static class SaltAndHash {
		final String salt;
		final String hash;

		SaltAndHash(String salt, String hash) {
			this.salt = salt;
			this.hash = hash;
		}

		@Override
		public boolean equals(Object o) {
			if (this == o)
				return true;
			if (o == null || getClass() != o.getClass())
				return false;

			SaltAndHash that = (SaltAndHash) o;

			if (salt != null ? !salt.equals(that.salt) : that.salt != null)
				return false;
			return hash != null ? hash.equals(that.hash) : that.hash == null;

		}

		@Override
		public int hashCode() {
			int result = salt != null ? salt.hashCode() : 0;
			result = 31 * result + (hash != null ? hash.hashCode() : 0);
			return result;
		}
	}
}
