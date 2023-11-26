from browser_history.browsers import Chrome
from browser_history.browsers import Firefox
from browser_history.browsers import Brave
from browser_history.browsers import Chromium
from browser_history.browsers import Edge
from browser_history.browsers import LibreWolf
from browser_history.browsers import Opera
from browser_history.browsers import OperaGX
from browser_history.browsers import Safari
from browser_history.browsers import Vivaldi
import chardet
import csv

def history_chrome():
    try:
        with open('brower_history.csv', 'a', newline='') as f:
            csv_writer = csv.writer(f)
            try:
                f = Chrome()
                print("[+] Chrome 파싱 시작")
                outputs = f.fetch_history()
                his = outputs.histories
                for i in his:
                    csv_writer.writerow([i[0], 'Chrome', i[1], i[2]])
            except Exception as e:
                print(f"[-] Browser History(Chrome) 파싱 중 에러 발생 : {e} ")
    except Exception as e:
        print(f"[-] browser_history.csv 파일 관련 에러 발생 : {e}")
        
def history_firefox():
    try:
        with open('brower_history.csv', 'a', newline='') as f:
            csv_writer = csv.writer(f)
            try:
                f = Firefox()
                print("[+] Firefox 파싱 시작")
                outputs = f.fetch_history()
                his = outputs.histories
                for i in his:
                    csv_writer.writerow([i[0], 'Firefox', i[1], i[2]])
            except Exception as e:
                print(f"[-] Browser History(FireFox) 파싱 중 에러 발생 : {e} ")
    except Exception as e:
        print(f"[-] browser_history.csv 파일 관련 에러 발생 : {e}")
        
def history_brave():
    try:
        with open('brower_history.csv', 'a', newline='') as f:
            csv_writer = csv.writer(f)
            try:
                f = Brave()
                print("[+] Brave 파싱 시작")
                outputs = f.fetch_history()
                his = outputs.histories
                for i in his:
                    csv_writer.writerow([i[0], 'Brave', i[1], i[2]])
            except Exception as e:
                print(f"[-] Browser History(Brave) 파싱 중 에러 발생 : {e} ")
    except Exception as e:
        print(f"[-] browser_history.csv 파일 관련 에러 발생 : {e}")
        
def history_chromium():
    try:
        with open('brower_history.csv', 'a', newline='') as f:
            csv_writer = csv.writer(f)
            try:
                f = Chromium()
                print("[+] Chromium 파싱 시작")
                outputs = f.fetch_history()
                his = outputs.histories
                for i in his:
                    csv_writer.writerow([i[0], 'Chromium', i[1], i[2]])
            except Exception as e:
                print(f"[-] Browser History(Chromium) 파싱 중 에러 발생 : {e} ")
    except Exception as e:
        print(f"[-] browser_history.csv 파일 관련 에러 발생 : {e}")
        
def history_edge():
    try:
        with open('brower_history.csv', 'a', newline='') as f:
            csv_writer = csv.writer(f)
            try:
                f = Edge()
                print("[+] Edge 파싱 시작")
                outputs = f.fetch_history()
                his = outputs.histories
                for i in his:
                    csv_writer.writerow([i[0], 'Edge', i[1], i[2]])
            except Exception as e:
                print(f"[-] Browser History(Edge) 파싱 중 에러 발생 : {e} ")
    except Exception as e:
        print(f"[-] browser_history.csv 파일 관련 에러 발생 : {e}")
        
def history_librewolf():
    try:
        with open('brower_history.csv', 'a', newline='') as f:
            csv_writer = csv.writer(f)
            try:
                f = LibreWolf()
                print("[+] LibreWolf 파싱 시작")
                outputs = f.fetch_history()
                his = outputs.histories
                for i in his:
                    csv_writer.writerow([i[0], 'LibreWolf', i[1], i[2]])
            except Exception as e:
                print(f"[-] Browser History(LibreWolf) 파싱 중 에러 발생 : {e} ")
    except Exception as e:
        print(f"[-] browser_history.csv 파일 관련 에러 발생 : {e}")
        
def history_opera():
    try:
        with open('brower_history.csv', 'a', newline='') as f:
            csv_writer = csv.writer(f)
            try:
                f = Opera()
                print("[+] Opera 파싱 시작")
                outputs = f.fetch_history()
                his = outputs.histories
                for i in his:
                    csv_writer.writerow([i[0], 'Opera', i[1], i[2]])
            except Exception as e:
                print(f"[-] Browser History(Opera) 파싱 중 에러 발생 : {e} ")
    except Exception as e:
        print(f"[-] browser_history.csv 파일 관련 에러 발생 : {e}")
        
def history_operagx():
    try:
        with open('brower_history.csv', 'a', newline='') as f:
            csv_writer = csv.writer(f)
            try:
                f = OperaGX()
                print("[+] OperaGX 파싱 시작")
                outputs = f.fetch_history()
                his = outputs.histories
                for i in his:
                    csv_writer.writerow([i[0], 'OperaGX', i[1], i[2]])
            except Exception as e:
                print(f"[-] Browser History(OperaGX) 파싱 중 에러 발생 : {e} ")
    except Exception as e:
        print(f"[-] browser_history.csv 파일 관련 에러 발생 : {e}")
        
def history_safari():
    try:
        with open('brower_history.csv', 'a', newline='') as f:
            csv_writer = csv.writer(f)
            try:
                f = Safari()
                print("[+] Safari 파싱 시작")
                outputs = f.fetch_history()
                his = outputs.histories
                for i in his:
                    csv_writer.writerow([i[0], 'Safari', i[1], i[2]])
            except Exception as e:
                print(f"[-] Browser History(Safari) 파싱 중 에러 발생 : {e} ")
    except Exception as e:
        print(f"[-] browser_history.csv 파일 관련 에러 발생 : {e}")
        
def history_vivaldi():
    try:
        with open('brower_history.csv', 'a', newline='') as f:
            csv_writer = csv.writer(f)
            try:
                f = Vivaldi()
                print("[+] Vivaldi 파싱 시작")
                outputs = f.fetch_history()
                his = outputs.histories
                for i in his:
                    csv_writer.writerow([i[0], 'Vivaldi', i[1], i[2]])
            except Exception as e:
                print(f"[-] Browser History(Vivaldi) 파싱 중 에러 발생 : {e} ")
    except Exception as e:
        print(f"[-] browser_history.csv 파일 관련 에러 발생 : {e}")
        
def main():
    with open('brower_history.csv', 'w', newline='') as f:
        csv_writer = csv.writer(f)
        csv_writer.writerow(['Time Stamp', 'Brower', 'URL Link', 'Explain'])
        history_chrome()
        history_firefox()
        history_brave()
        history_chromium()
        history_edge()
        history_librewolf()
        history_opera()
        history_operagx()
        history_safari()
        history_vivaldi()
