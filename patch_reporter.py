import re

with open("climatetrust/reporter.py", "r") as f:
    text = f.read()

# Fix JS template literals and object braces in f-string
text = text.replace("{hour12: false}", "{{hour12: false}}")
text = text.replace("${time}", "${{time}}")
text = text.replace("${color}", "${{color}}")
text = text.replace("${type}", "${{type}}")
text = text.replace("${details}", "${{details}}")
text = text.replace("${Math.floor(Math.random()*10000000 + 19000000)}", "${{Math.floor(Math.random()*10000000 + 19000000)}}")

with open("climatetrust/reporter.py", "w") as f:
    f.write(text)

