/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.christofreichardt.crypto;

import de.christofreichardt.crypto.ecschnorrsignature.ECSchnorrKeyPairGeneratorUnit;
import de.christofreichardt.junit.MySuite;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

/**
 *
 * @author Christof Reichardt
 */
@RunWith(MySuite.class)
@Suite.SuiteClasses({
  DummyUnit.class,
  ExperimentalUnit.class,
  ECSchnorrKeyPairGeneratorUnit.class
})
public class ECSchnorrSignatureSuite {
}
