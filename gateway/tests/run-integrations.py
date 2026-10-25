"""Run isolated gateway integration suites with bounded concurrency and individual logs."""
import argparse
import concurrent.futures
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

SUITES = 'shutdown timing proxy pools rate-limit policy cache tls accounts-alerts credentials reliability-balancing routing pages monitoring backup mfa diagnostics scheduled-backups config-history templates compression forward-auth cluster cli trust'.split()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jobs',type=int,choices=range(1,5),default=3)
    parser.add_argument('--log-dir',type=Path)
    parser.add_argument('suites',nargs='*',choices=SUITES)
    args=parser.parse_args()
    suites=args.suites or SUITES
    directory=args.log_dir or Path(tempfile.mkdtemp(prefix='embergate-integrations-'))
    directory.mkdir(parents=True,exist_ok=True)
    tests=Path(__file__).resolve().parent
    def run(suite):
        started=time.monotonic();path=directory/(suite+'.log')
        with path.open('w') as output:
            process=subprocess.Popen([sys.executable,str(tests/(suite+'-smoke.py'))],stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
            try:code=process.wait(timeout=300)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL);process.wait();code=124
                output.write('\nIntegration suite exceeded 300 seconds.\n')
        return suite,code,time.monotonic()-started,path
    failed=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
        futures=[executor.submit(run,suite) for suite in suites]
        for future in concurrent.futures.as_completed(futures):
            suite,code,elapsed,path=future.result()
            print(f'{suite}: {"PASS" if code==0 else "FAIL"} ({elapsed:.1f}s)',flush=True)
            if code:
                failed.append(suite);print(path.read_text(),flush=True)
    print(f'{len(suites)-len(failed)}/{len(suites)} suites passed. Logs: {directory}',flush=True)
    return int(bool(failed))

if __name__=='__main__':sys.exit(main())
