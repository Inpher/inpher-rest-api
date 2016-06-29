package rest.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

public class AutoDeleteFileInputStream extends FileInputStream {
    private File file;
    
    public AutoDeleteFileInputStream(File file) throws FileNotFoundException {
        super(file);
        this.file=file;
    }
    
    public void close() {
        try {
            super.close();
        } catch (IOException dontCare) {}
        try {
            file.delete();
        } catch (Exception dontCareEither) {}
    }
}
