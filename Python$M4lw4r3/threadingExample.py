import threading
import time
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG,
    format="%(asctime)s - %(threadName)s - %(message)s"
)

# Function to simulate a task that takes some time to execute
def task():
    logging.debug("Task started")
    time.sleep(10)  # Simulating a long-running task
    logging.debug("Task completed")

# Single-threaded execution
start_time = time.time()
task()  # Execute the task
end_time = time.time()
print(f"Single-threaded execution time: {end_time - start_time} seconds")

# Multi-threaded execution
start_time = time.time()
threads = []
for i in range(5):  # Create 5 threads to execute the task concurrently
    t = threading.Thread(target=task, name=f"Thread-{i+1}")
    threads.append(t)
    t.start()

# Wait for all threads to complete
for t in threads:
    t.join()

end_time = time.time()
print(f"Multi-threaded execution time: {end_time - start_time} seconds")
