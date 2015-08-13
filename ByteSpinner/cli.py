import click
import os.path

from .spinner import Spinner


@click.group()
@click.pass_context
def cli(ctx):
    """Symmetric encryption using an iterative and multi-key XOR-based
    algorithm."""
    pass


@cli.command()
@click.argument('KEY_FILE', type=click.Path(exists=False))
@click.option('--length', default=256,
              help='Number of random bytes to use in the base XOR (should be '
              'longer than the messages you wish to encrypt).')
@click.option('--iterations', default=10,
              help='Number of iterations for encryption/decryption.')
@click.pass_context
def gen(ctx, key_file, length, iterations):
    """Generate a new symmetric encryption key."""

    # check inputs
    if length <= 0:
        ctx.fail('Length must be an integer > 0.')
    if iterations <= 0:
        ctx.fail('Iterations must be an integer > 0.')
    if os.path.exists(key_file):
        ctx.fail('KEY_FILE already exists.')

    # generate and write new key
    click.echo('Creating key file: %s' % key_file)
    k = Spinner.generate(length, iterations)
    f = open(key_file, 'w')
    f.write(k.dumps())
    f.close()


@cli.command()
@click.argument('KEY_FILE', type=click.File('r'))
@click.pass_context
def info(ctx, key_file):
    """Show properties of a symmetric key."""

    # print info
    k = Spinner.loads(key_file.read())
    click.echo('XOR base length: %d' % k.get_num_bytes())
    click.echo('Iterations: %d' % k.get_num_iterations())


@cli.command()
@click.argument('KEY_FILE', type=click.File('r'))
@click.argument('PT_FILE', type=click.File('rb'))
@click.argument('CT_FILE', type=click.Path(exists=False))
@click.pass_context
def enc(ctx, key_file, pt_file, ct_file):
    """Encrypt a plaintext file."""

    # do encryption
    k = Spinner.loads(key_file.read())
    ct = k.encrypt(bytearray(pt_file.read()))
    f = open(ct_file, 'wb')
    f.write(ct)
    f.close()
    click.echo('Wrote ciphertext to %s' % ct_file)


@cli.command()
@click.argument('KEY_FILE', type=click.File('r'))
@click.argument('CT_FILE', type=click.File('rb'))
@click.argument('PT_FILE', type=click.Path(exists=False))
@click.pass_context
def dec(ctx, key_file, ct_file, pt_file):
    """Decrypt a ciphertext file."""

    # do decryption
    k = Spinner.loads(key_file.read())
    pt = k.decrypt(bytearray(ct_file.read()))
    f = open(pt_file, 'wb')
    f.write(pt)
    f.close()
    click.echo('Wrote plaintext to %s' % pt_file)


if __name__ == '__main__':
    cli(obj={})
