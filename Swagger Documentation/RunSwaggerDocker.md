
1. ```cd SwaggerDocumentation/swagger-ui```

2. Run the container:
   ```bash
   docker run -d -p 6080:8080 -v $(pwd):/usr/share/nginx/html <name>
   ```

   - `-d` → detached mode (runs in background)  
   - `-p 6080:8080` → orwards container’s port `8080` to local port `6080` (host port can be changed).

3. Open Swagger UI in your browser:  
    [http://localhost:6080](http://localhost:6080)