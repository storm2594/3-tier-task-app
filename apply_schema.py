import pg8000
import os

def apply_schema():
    host = "task-manager-db.c1mcem8e8paq.us-east-1.rds.amazonaws.com"
    user = "postgres"
    password = "YourSecurePassword123!"
    database = "taskmanager"
    
    print(f"Connecting to {host}...")
    try:
        conn = pg8000.connect(
            host=host,
            user=user,
            password=password,
            database=database
        )
        cursor = conn.cursor()
        
        print("Reading schema.sql...")
        with open('database/schema.sql', 'r') as f:
            schema_sql = f.read()
            
        print("Applying schema...")
        # pg8000 might not support multiple statements in one execute() depending on version
        # but the safest way is to split by semicolon if they are simple
        for statement in schema_sql.split(';'):
            if statement.strip():
                cursor.execute(statement)
        
        conn.commit()
        print("Schema applied successfully!")
        
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error applying schema: {e}")

if __name__ == "__main__":
    apply_schema()
