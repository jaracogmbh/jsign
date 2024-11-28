package net.jsign.util;

import net.jsign.exception.FileNotFoundException;
import net.jsign.exception.NoPropertiesInPropertyFileException;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;

public class PropertyLoader {
    Logger logger = Logger.getLogger(this.getClass().getName());
    public Properties loadPropertyFile(String filename) throws FileNotFoundException, NoPropertiesInPropertyFileException {
        logger.info("Loading properties from file " + filename);
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream(filename);
        Properties properties1 = new Properties();
        try{
            properties1.load(inputStream);
        } catch (IOException e) {
            throw new FileNotFoundException("file " + filename + " not found, " + e.getMessage(), e);
        }
        if (properties1.isEmpty()) {
            throw new NoPropertiesInPropertyFileException("Property file " + filename + " seems to be empty!");
        }
        for (Map.Entry<Object, Object> entry : properties1.entrySet()) {
            logger.info("key: " + entry.getKey() + "; " + "value: " + entry.getValue());
        }
        return properties1;
    }

    public String extractPasswordForUsername(Properties properties, String username) {
        return properties.getProperty(username);
    }

    public boolean isPasswordExistence(Properties properties, String username) {
        return properties.containsKey(username);
    }
}
